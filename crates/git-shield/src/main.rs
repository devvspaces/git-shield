//! `git-shield`: inspect incoming git changes before they touch your working tree.
//!
//! Installed on PATH as `git-shield`, it is also available as `git shield`.

mod audit;
mod ci;
mod config;
mod doctor;
mod install;
mod worktree;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use rayon::prelude::*;
use shield_core::{
    Attestations, CommitInfo, ForcePushInfo, PrState, PushedBy, RemoteVerification, Report, ScanContext, Severity,
    TipSource,
};
use shield_git::trust::TrustStore;
use shield_git::{GitRepo, ObjectId, ProvenanceInput, hardened::HardenedGit};
use std::collections::{HashMap, HashSet};
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "git-shield", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a revision range already present locally (no network).
    ///
    /// RANGE is `A..B` (what B brings on top of A), or `B` (= HEAD..B).
    /// Defaults to HEAD..<upstream of current branch>.
    Scan {
        range: Option<String>,
        /// A tip you had before (repeatable). Reports a rewrite if the range end no longer contains it.
        #[arg(long, value_name = "REV")]
        previous_tip: Vec<String>,
        /// Also look up the branch's force-push history on GitHub (network).
        #[arg(long)]
        github: bool,
        /// GitHub branch whose push history explains the range, when the range
        /// end is not a remote-tracking ref (default: the upstream branch, if it
        /// contains the range end).
        #[arg(long, value_name = "BRANCH", requires = "github")]
        github_branch: Option<String>,
        /// Forensic depth: read far more GitHub history, commits and pull
        /// requests than the defaults used by check/pull.
        #[arg(long)]
        deep: bool,
        #[command(flatten)]
        common: Common,
    },
    /// Scan what a GitHub push or pull request brings in, inside a workflow run.
    ///
    /// The range comes from $GITHUB_EVENT_PATH: `base..head` for a pull request,
    /// `before..after` for a push (a forced push is checked as a rewrite).
    /// Writes workflow annotations and the job summary; exits 2 when a finding
    /// at or above --fail-on is not accepted, else 0.
    Ci {
        /// Scan this range instead of the one the event implies.
        range: Option<String>,
        /// Event payload (default: $GITHUB_EVENT_PATH).
        #[arg(long, value_name = "FILE")]
        event: Option<PathBuf>,
        /// Event name (default: $GITHUB_EVENT_NAME).
        #[arg(long, value_name = "NAME")]
        event_name: Option<String>,
        /// Lowest severity that fails the job.
        #[arg(long, value_name = "SEVERITY", default_value = "high", value_parser = ci::parse_severity)]
        fail_on: shield_core::Severity,
        /// TOML file of `[[accept]] id = "…" reason = "…"` entries.
        #[arg(long, value_name = "FILE")]
        accept_file: Option<PathBuf>,
        /// Same format, read from the repository at the trusted side of the
        /// event (the PR base, or the branch before the push), never from the
        /// incoming commits.
        #[arg(long, value_name = "PATH")]
        accepts_path: Option<String>,
        /// Stay offline: no GitHub lookups.
        #[arg(long)]
        no_github: bool,
        /// Forensic depth, as `scan --deep`.
        #[arg(long)]
        deep: bool,
        #[command(flatten)]
        common: Common,
    },
    /// Fetch (hardened, objects only) and scan what a pull would bring in. Never merges.
    Check {
        #[command(flatten)]
        target: Target,
        /// Skip the fetch and scan the existing remote-tracking ref.
        #[arg(long)]
        no_fetch: bool,
        #[command(flatten)]
        common: Common,
    },
    /// Fetch, scan, and fast-forward only if nothing blocking was found.
    ///
    /// Merges exactly the commit that was scanned. Blocking findings must be
    /// accepted (`--accept ID`, or interactively on a terminal) to continue;
    /// accepted ids are remembered for this repository.
    Pull {
        #[command(flatten)]
        target: Target,
        /// Rebase local commits onto the scanned tip instead of requiring a fast-forward.
        #[arg(long, conflicts_with = "merge")]
        rebase: bool,
        /// Create a merge commit if a fast-forward is not possible.
        #[arg(long)]
        merge: bool,
        /// Why the accepted findings are fine (stored with them).
        #[arg(long, value_name = "TEXT")]
        reason: Option<String>,
        /// Accepted for `git pull` compatibility (fast-forward is already the default).
        #[arg(long, hide = true)]
        ff_only: bool,
        /// Accepted for `git pull` compatibility.
        #[arg(long, hide = true)]
        no_rebase: bool,
        #[command(flatten)]
        common: Common,
    },
    /// Show or change what git-shield remembers for this repository
    /// (accepted findings and the last tip pulled per ref).
    Trust {
        #[command(subcommand)]
        action: TrustAction,
    },
    /// Inspect a repository or folder as it is on disk, before running git, an
    /// editor or an agent in it (for code that arrived as files: zip, tarball,
    /// shared drive). Reads files and `.git/config`/hooks; executes nothing.
    Audit {
        /// Directory to audit (default: `-C`, i.e. the current directory).
        path: Option<PathBuf>,
        /// Audit a committed tree (e.g. `HEAD`) instead of the files on disk.
        #[arg(long, value_name = "REV")]
        rev: Option<String>,
        #[command(flatten)]
        common: Common,
    },
    /// Clone without checking out, scan the whole tree, then check out only if
    /// nothing blocking was found (or it was accepted).
    Clone {
        url: String,
        dir: Option<PathBuf>,
        /// Branch to clone (default: the remote's HEAD).
        #[arg(long, short)]
        branch: Option<String>,
        /// Why accepted findings are fine (stored with them).
        #[arg(long, value_name = "TEXT")]
        reason: Option<String>,
        /// Do not ask GitHub about commit signatures and pull requests.
        #[arg(long)]
        no_github: bool,
        #[command(flatten)]
        common: Common,
    },
    /// Scan what switching to a branch/commit would write, then switch.
    Checkout {
        target: String,
        #[arg(long, value_name = "TEXT")]
        reason: Option<String>,
        /// Run git even if the local git config contains settings that execute programs.
        #[arg(long)]
        allow_unsafe_config: bool,
        /// Do not ask GitHub about commit signatures and pull requests.
        #[arg(long)]
        no_github: bool,
        #[command(flatten)]
        common: Common,
    },
    /// Check your own git, editor and AI-agent settings for risky defaults.
    /// Read-only: prints suggested fixes, never changes anything.
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// Make a plain `git pull` run `git shield pull` (a shell function).
    /// Prints the snippet; `--write` adds it to your shell rc between markers.
    Install {
        /// Shell to target (zsh, bash, fish); default from $SHELL.
        #[arg(long)]
        shell: Option<String>,
        /// File to edit instead of the shell's default rc file.
        #[arg(long, value_name = "FILE")]
        rc: Option<PathBuf>,
        /// Actually edit the rc file.
        #[arg(long)]
        write: bool,
    },
    /// Remove the block added by `install --write`.
    Uninstall {
        #[arg(long)]
        shell: Option<String>,
        #[arg(long, value_name = "FILE")]
        rc: Option<PathBuf>,
    },
    /// Show where the user config (allowlist) lives, and validate it.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Print the config file location.
    Path,
    /// Parse and validate the config file.
    Check,
}

#[derive(Subcommand)]
enum TrustAction {
    /// List trusted tips and accepted findings.
    List {
        #[arg(long, short = 'C', default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Forget accepted findings (they will block again), or a ref's trusted tip.
    #[command(group(clap::ArgGroup::new("what").required(true).args(["ids", "all", "ref_name"])))]
    Forget {
        /// Finding ids to forget.
        ids: Vec<String>,
        /// Forget every accepted finding.
        #[arg(long)]
        all: bool,
        /// Forget the trusted tip of this ref (e.g. origin/dev or refs/remotes/origin/dev).
        #[arg(long = "ref", value_name = "REF")]
        ref_name: Option<String>,
        #[arg(long, short = 'C', default_value = ".")]
        repo: PathBuf,
    },
}

#[derive(Args)]
struct Target {
    /// Remote name; defaults to the current branch's upstream remote.
    remote: Option<String>,
    /// Remote branch; defaults to the current branch's upstream branch.
    branch: Option<String>,
    /// Run git even if the local git config contains settings that execute programs.
    #[arg(long)]
    allow_unsafe_config: bool,
    /// Skip the GitHub force-push history lookup (stay offline after the fetch).
    #[arg(long)]
    no_github: bool,
}

#[derive(Args)]
struct Common {
    /// Repository path (defaults to the current directory).
    #[arg(long, short = 'C', default_value = ".")]
    repo: PathBuf,
    /// Emit the report as JSON.
    #[arg(long)]
    json: bool,
    /// Also write the report as SARIF 2.1.0 to FILE (for code scanning).
    #[arg(long, value_name = "FILE")]
    sarif: Option<PathBuf>,
    /// Also show info-level findings, and every finding of grouped rules.
    #[arg(long, short)]
    verbose: bool,
    /// Treat this finding id as reviewed (may be repeated).
    #[arg(long = "accept", value_name = "ID")]
    accept: Vec<String>,
    /// Disable colored output.
    #[arg(long)]
    no_color: bool,
    /// GitHub repository to query, when the remote URL does not say (e.g. an SSH host alias).
    #[arg(long, value_name = "OWNER/NAME")]
    github_repo: Option<String>,
    /// Skip local GPG/SSH verification of incoming commit signatures.
    #[arg(long)]
    no_verify_signatures: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("git-shield: error: {e:#}");
            ExitCode::from(3)
        }
    }
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn run(cli: Cli) -> Result<u8> {
    let scans = !matches!(
        cli.command,
        Command::Doctor { .. }
            | Command::Trust { .. }
            | Command::Config { .. }
            | Command::Install { .. }
            | Command::Uninstall { .. }
    );
    if scans {
        load_detectors()?;
    }
    match cli.command {
        Command::Scan { range, previous_tip, github, github_branch, deep, common } => {
            let repo = GitRepo::discover(&common.repo)?;
            let store = TrustStore::open(&repo)?;
            let (from, to, b, label) = resolve_range(&repo, range.as_deref())?;
            let given =
                previous_tip.iter().map(|r| Ok((repo.resolve(r)?, TipSource::Given))).collect::<Result<Vec<_>>>()?;
            let full = repo.full_ref_name(&b);
            let budget = if deep { Budget::DEEP } else { Budget::DEFAULT };
            let mut gh = KnownTips::default();
            let mut ref_name = full.clone();
            if github {
                let at_ref = full
                    .as_deref()
                    .and_then(|r| r.strip_prefix("refs/remotes/"))
                    .and_then(|r| r.split_once('/'))
                    .map(|(r, b)| (r.to_string(), b.to_string()));
                match at_ref.or_else(|| history_branch(&repo, to, github_branch.as_deref(), &common)) {
                    Some((remote, branch)) => {
                        let tracking = format!("refs/remotes/{remote}/{branch}");
                        gh = github_tips(
                            &repo,
                            &store,
                            &tracking,
                            &remote,
                            &branch,
                            to,
                            Some(from),
                            false,
                            budget,
                            &common,
                        );
                    }
                    // No branch to ask about: commits and PRs can still be checked.
                    None => gh.session = gh_session(&repo, None, &common),
                }
            }
            gh.budget = budget;
            gh.tips.splice(0..0, given);
            // Provenance needs a ref; without one, use the range end itself.
            if ref_name.is_none() && !gh.tips.is_empty() {
                ref_name = Some(b.clone());
            }
            let ctx = build_context(&repo, &store, from, to, label, ref_name.as_deref(), &gh, &common)?;
            let report = scan(&ctx);
            Ok(emit(&report, &accepted(&common, Some(&store), &report, Some(&repo))?, &common))
        }
        Command::Check { target, no_fetch, common } => {
            let repo = GitRepo::discover(&common.repo)?;
            let (remote, branch) = target_names(&repo, &target)?;
            let tracking = format!("refs/remotes/{remote}/{branch}");
            let mut prefetch = None;
            if !no_fetch {
                preflight(&repo, target.allow_unsafe_config, false, &common)?;
                prefetch = repo.ref_tip(&tracking);
                fetch(&repo, &remote, &branch, &common)?;
            }
            // Re-open so refs updated by the fetch are visible.
            let repo = GitRepo::discover(&common.repo)?;
            let store = TrustStore::open(&repo)?;
            let to = repo.resolve(&tracking).with_context(|| format!("remote-tracking ref {tracking} not found"))?;
            let mut gh = if target.no_github {
                KnownTips::default()
            } else {
                github_tips(
                    &repo,
                    &store,
                    &tracking,
                    &remote,
                    &branch,
                    to,
                    repo.resolve("HEAD").ok(),
                    !no_fetch,
                    Budget::DEFAULT,
                    &common,
                )
            };
            gh.tips.splice(0..0, prefetch.map(|p| (p, TipSource::PreFetch)));
            let repo = if gh.fetched { GitRepo::discover(&common.repo)? } else { repo };
            let from = repo.resolve("HEAD")?;
            let ctx = build_context(
                &repo,
                &store,
                from,
                to,
                format!("HEAD..{remote}/{branch}"),
                Some(&tracking),
                &gh,
                &common,
            )?;
            let report = scan(&ctx);
            Ok(emit(&report, &accepted(&common, Some(&store), &report, Some(&repo))?, &common))
        }
        Command::Pull { target, rebase, merge, reason, common, .. } => pull(target, rebase, merge, reason, common),
        Command::Trust { action } => trust(action),
        Command::Audit { path, rev, common } => audit::run(path, rev, &common),
        Command::Ci { range, event, event_name, fail_on, accept_file, accepts_path, no_github, deep, common } => {
            ci::run(ci::CiArgs {
                range,
                event,
                event_name,
                fail_on,
                accept_file,
                accepts_path,
                no_github,
                deep,
                common,
            })
        }
        Command::Doctor { json } => doctor::run(json),
        Command::Install { shell, rc, write } => install::install(shell.as_deref(), rc, write),
        Command::Uninstall { shell, rc } => install::uninstall(shell.as_deref(), rc),
        Command::Clone { url, dir, branch, reason, no_github, common } => {
            worktree::clone(&url, dir, branch.as_deref(), reason, no_github, &common)
        }
        Command::Checkout { target, reason, allow_unsafe_config, no_github, common } => {
            worktree::checkout(&target, reason, allow_unsafe_config, no_github, &common)
        }
        Command::Config { action } => {
            let path = config::path().map(|p| p.display().to_string()).unwrap_or_else(|| "(no HOME)".into());
            match action {
                ConfigAction::Path => println!("{path}"),
                ConfigAction::Check => {
                    let cfg = config::load()?;
                    println!(
                        "{path}: OK ({} allow entr{})",
                        cfg.allow.len(),
                        if cfg.allow.len() == 1 { "y" } else { "ies" }
                    );
                }
            }
            Ok(0)
        }
    }
}

fn trust(action: TrustAction) -> Result<u8> {
    match action {
        TrustAction::List { repo, json } => {
            let repo = GitRepo::discover(&repo)?;
            let store = TrustStore::open(&repo)?;
            if json {
                let v = serde_json::json!({
                    "path": store.path(),
                    "repo_path": store.data.repo_path,
                    "refs": store.data.refs,
                    "accepted": store.data.accepted,
                });
                println!("{}", serde_json::to_string_pretty(&v)?);
                return Ok(0);
            }
            println!("Trust store: {}", store.path().display());
            if store.data.refs.is_empty() {
                println!("\nNo trusted tips yet (they are recorded by `git shield pull`).");
            } else {
                println!("\nTrusted tips:");
                for (r, t) in &store.data.refs {
                    println!("  {:<32} {}  {}", display_ref(r), &t.tip[..t.tip.len().min(9)], date(t.at));
                }
            }
            if store.data.accepted.is_empty() {
                println!("\nNo accepted findings.");
            } else {
                println!("\nAccepted findings:");
                for a in &store.data.accepted {
                    let tip = a.tip.as_deref().map(|t| format!("  at {}", &t[..t.len().min(9)])).unwrap_or_default();
                    println!("  {:<18} {}{tip}  \"{}\"", a.id, date(a.at), a.reason);
                }
            }
            Ok(0)
        }
        TrustAction::Forget { ids, all, ref_name, repo } => {
            let repo = GitRepo::discover(&repo)?;
            let mut store = TrustStore::open(&repo)?;
            let mut code = 0;
            if all {
                println!("Forgot {} accepted finding(s).", store.forget_all());
            }
            for id in &ids {
                if store.forget(id) {
                    println!("Forgot {id}.");
                } else {
                    eprintln!("git-shield: {id} was not accepted.");
                    code = 1;
                }
            }
            if let Some(r) = ref_name {
                let full = repo.full_ref_name(&r).unwrap_or(r.clone());
                if store.forget_ref(&full) || store.forget_ref(&r) {
                    println!("Forgot the trusted tip of {}.", display_ref(&full));
                } else {
                    eprintln!("git-shield: no trusted tip recorded for {r}.");
                    code = 1;
                }
            }
            store.save().with_context(|| format!("writing trust store {}", store.path().display()))?;
            Ok(code)
        }
    }
}

fn display_ref(name: &str) -> &str {
    name.strip_prefix("refs/remotes/").or_else(|| name.strip_prefix("refs/heads/")).unwrap_or(name)
}

fn date(secs: i64) -> String {
    shield_core::utc_date(secs)
}

fn pull(target: Target, rebase: bool, merge: bool, reason: Option<String>, common: Common) -> Result<u8> {
    let repo = GitRepo::discover(&common.repo)?;
    let (remote, branch) = target_names(&repo, &target)?;
    let tracking = format!("refs/remotes/{remote}/{branch}");

    preflight(&repo, target.allow_unsafe_config, true, &common)?;
    let prefetch = repo.ref_tip(&tracking);
    fetch(&repo, &remote, &branch, &common)?;

    let repo = GitRepo::discover(&common.repo)?;
    let mut store = TrustStore::open(&repo)?;
    let tip = repo.resolve(&tracking).with_context(|| format!("remote-tracking ref {tracking} not found"))?;
    let mut gh = if target.no_github {
        KnownTips::default()
    } else {
        github_tips(
            &repo,
            &store,
            &tracking,
            &remote,
            &branch,
            tip,
            repo.resolve("HEAD").ok(),
            true,
            Budget::DEFAULT,
            &common,
        )
    };
    gh.tips.splice(0..0, prefetch.map(|p| (p, TipSource::PreFetch)));
    let repo = if gh.fetched { GitRepo::discover(&common.repo)? } else { repo };
    let head = repo.resolve("HEAD")?;
    let ctx =
        build_context(&repo, &store, head, tip, format!("HEAD..{remote}/{branch}"), Some(&tracking), &gh, &common)?;
    let report = scan(&ctx);
    let mut accepted = accepted(&common, Some(&store), &report, Some(&repo))?;
    emit(&report, &accepted, &common);

    let up_to_date = repo.is_ancestor(tip, head)?;
    let fast_forward = repo.is_ancestor(head, tip)?;
    if !up_to_date && !fast_forward && !rebase && !merge {
        bail!(
            "HEAD and {remote}/{branch} have diverged; nothing was changed. \
             Re-run with --rebase or --merge (the scanned commit {} is what will be integrated).",
            short(&tip)
        );
    }

    let Some(decision) = gate(&report, &mut accepted, &common, reason, "pull", "nothing was merged")? else {
        return Ok(2);
    };

    if up_to_date {
        if !common.json {
            eprintln!("git-shield: already up to date.");
        }
    } else {
        let workdir = repo.workdir().context("pull needs a working tree")?;
        let git = HardenedGit::new(&workdir)?;
        // Integrate exactly the scanned commit, never the (movable) ref name.
        let sha = tip.to_string();
        let how = if fast_forward {
            git.merge_ff_only(&sha)?;
            "fast-forward"
        } else if rebase {
            git.rebase(&sha)?;
            "rebased"
        } else {
            git.merge(&sha)?;
            "merged"
        };
        if !common.json {
            eprintln!("git-shield: {} → {} ({how})", short(&head), short(&tip));
        }
    }

    let t = now();
    let tip_hex = tip.to_string();
    decision.record(&mut store, &tip_hex, t);
    store.set_tip(&tracking, &tip_hex, t);
    store.save().with_context(|| format!("writing trust store {}", store.path().display()))?;

    Ok(report.exit_code(&accepted) as u8)
}

/// What the user decided about a report's blocking findings.
struct Decision {
    /// Ids accepted in this run (`--accept` or the prompt), to remember.
    newly_accepted: Vec<String>,
    reason: String,
}

impl Decision {
    fn record(&self, store: &mut TrustStore, tip: &str, now: i64) {
        for id in &self.newly_accepted {
            store.accept(id, &self.reason, Some(tip), now);
        }
    }
}

/// Block, or let the user accept the blocking findings. `None` means stop
/// (already explained on stderr); the caller exits 2. Never prompts without a
/// terminal.
fn gate(
    report: &Report,
    accepted: &mut HashSet<String>,
    common: &Common,
    reason: Option<String>,
    verb: &str,
    unchanged: &str,
) -> Result<Option<Decision>> {
    let mut newly_accepted: Vec<String> =
        common.accept.iter().filter(|id| report.findings.iter().any(|f| &f.id.0 == *id)).cloned().collect();
    let blocking: Vec<String> = report.blocking(accepted).map(|f| f.id.0.clone()).collect();
    let mut reason = reason;
    if !blocking.is_empty() {
        if !interactive(common) {
            eprintln!("git-shield: {verb} blocked; {unchanged}.");
            return Ok(None);
        }
        let ok = dialoguer::Confirm::new()
            .with_prompt(format!("Accept {} blocking finding(s) and {verb} anyway?", blocking.len()))
            .default(false)
            .interact()
            .unwrap_or(false);
        if !ok {
            eprintln!("git-shield: {verb} aborted; {unchanged}.");
            return Ok(None);
        }
        if reason.is_none() {
            let r: String = dialoguer::Input::new()
                .with_prompt("Reason (stored with the acceptance)")
                .allow_empty(true)
                .interact_text()
                .unwrap_or_default();
            reason = Some(r);
        }
        accepted.extend(blocking.iter().cloned());
        newly_accepted.extend(blocking);
    }
    let reason = reason.filter(|r| !r.trim().is_empty()).unwrap_or_else(|| "accepted via --accept".into());
    Ok(Some(Decision { newly_accepted, reason }))
}

fn short(id: &ObjectId) -> String {
    id.to_hex_with_len(9).to_string()
}

fn interactive(common: &Common) -> bool {
    !common.json && std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

fn target_names(repo: &GitRepo, target: &Target) -> Result<(String, String)> {
    Ok(match (&target.remote, &target.branch) {
        (Some(r), Some(b)) => (r.clone(), b.clone()),
        (r, b) => {
            let up = repo.upstream()?;
            (r.clone().unwrap_or(up.remote), b.clone().unwrap_or(up.branch))
        }
    })
}

fn fetch(repo: &GitRepo, remote: &str, branch: &str, common: &Common) -> Result<()> {
    let workdir = repo.workdir().unwrap_or_else(|| repo.git_dir().to_path_buf());
    if !common.json {
        eprintln!("git-shield: fetching {remote} {branch} (hardened, no checkout)…");
    }
    HardenedGit::new(&workdir)?.fetch(remote, Some(branch))?;
    Ok(())
}

/// Scan context plus provenance for `ref_name` (when the target is a ref).
#[allow(clippy::too_many_arguments)]
fn build_context(
    repo: &GitRepo,
    store: &TrustStore,
    from: ObjectId,
    to: ObjectId,
    label: String,
    ref_name: Option<&str>,
    known: &KnownTips,
    common: &Common,
) -> Result<ScanContext> {
    let mut ctx = repo.incoming(from, to, label)?;
    let range = ctx.base.as_deref().zip(ctx.tip.as_deref());
    ctx.attest = attest(repo, &ctx.commits, range, known, common, true)?;
    let Some(ref_name) = ref_name else { return Ok(ctx) };
    let t = now();
    let mut extra = known.tips.clone();
    let trusted = store.trusted_tip(ref_name);
    if let Some(tt) = trusted
        && let Ok(oid) = ObjectId::from_hex(tt.tip.as_bytes())
    {
        extra.push((oid, TipSource::TrustStore));
    }
    let base = ctx.base.as_deref().and_then(|b| ObjectId::from_hex(b.as_bytes()).ok());
    let input = ProvenanceInput {
        ref_name,
        new_tip: to,
        base,
        commits: &ctx.commits,
        extra: &extra,
        pushers: &known.pushers,
        reflog_since: trusted.map_or(t - shield_git::REFLOG_WINDOW_SECS, |tt| tt.at),
        now: t,
    };
    ctx.provenance = Some(repo.provenance(&input)?);
    Ok(ctx)
}

/// Previous tips of the scanned ref known from outside its reflog.
#[derive(Default)]
struct KnownTips {
    tips: Vec<(ObjectId, TipSource)>,
    /// Replaced tip → the force-push that replaced it.
    pushers: HashMap<ObjectId, ForcePushInfo>,
    /// Missing objects were fetched; re-open the repository to see them.
    fetched: bool,
    /// GitHub access for commit verification, PR lookups and push attribution.
    session: Option<GhSession>,
    /// Branch on GitHub whose activity explains who pushed what.
    branch: Option<String>,
    /// Last pull recorded in the trust store (unix seconds).
    since: Option<i64>,
    budget: Budget,
}

/// How much GitHub history and how many commits one scan looks at.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Budget {
    /// Activity-log pages (100 events each).
    activity_pages: usize,
    /// Signed commits verified locally.
    sig_checks: usize,
    /// Signed commits GitHub did not list in compare, looked up by id.
    remote_sigs: usize,
    /// Distinct "Merge pull request #N" numbers looked up.
    prs: usize,
}

impl Budget {
    pub(crate) const DEFAULT: Budget = Budget { activity_pages: 10, sig_checks: 2000, remote_sigs: 2000, prs: 1000 };
    /// `scan --deep`.
    const DEEP: Budget = Budget { activity_pages: 50, sig_checks: 5000, remote_sigs: 5000, prs: 5000 };
}

impl Default for Budget {
    fn default() -> Self {
        Budget::DEFAULT
    }
}

/// REST lookups made at most when GraphQL is unavailable.
const REST_FALLBACK: usize = 100;

struct GhSession {
    client: shield_github::Client,
    owner: String,
    name: String,
}

/// GitHub client and repository slug, or `None` (with a note when useful).
/// `remote` defaults to the upstream remote, then `origin`.
fn gh_session(repo: &GitRepo, remote: Option<&str>, common: &Common) -> Option<GhSession> {
    let (owner, name) = match &common.github_repo {
        Some(s) => match shield_github::parse_slug(s) {
            Some(x) => x,
            None => {
                note(&format!("--github-repo expects OWNER/NAME, got `{s}`"));
                return None;
            }
        },
        None => {
            let remote = remote.map(str::to_string).or_else(|| repo.upstream().ok().map(|u| u.remote));
            let url = repo.remote_url(remote.as_deref().unwrap_or("origin"))?;
            // Not a GitHub remote: nothing to ask, nothing to say.
            shield_github::repo_slug(&url)?
        }
    };
    match shield_github::Client::from_env() {
        Ok(client) => Some(GhSession { client, owner, name }),
        Err(e) => {
            note(&e);
            None
        }
    }
}

/// At most this many replaced tips are fetched by SHA when missing locally.
const MAX_SHA_FETCHES: usize = 5;

fn note(msg: &str) {
    eprintln!("git-shield: note: {msg}");
}

/// Ask GitHub which force-pushes `branch` went through, and keep those that
/// still matter for `new_tip`: pushed by someone other than the token's owner,
/// after the last pull recorded in the trust store, and whose result is still
/// part of the history being pulled. Never fails: problems become notes.
#[allow(clippy::too_many_arguments)]
fn github_tips(
    repo: &GitRepo,
    store: &TrustStore,
    ref_name: &str,
    remote: &str,
    branch: &str,
    new_tip: ObjectId,
    head: Option<ObjectId>,
    fetch_missing: bool,
    budget: Budget,
    common: &Common,
) -> KnownTips {
    let since = store.trusted_tip(ref_name).map(|t| t.at);
    let mut out = KnownTips { branch: Some(branch.to_string()), since, budget, ..Default::default() };
    let Some(session) = gh_session(repo, Some(remote), common) else { return out };
    let client = &session.client;
    let slug = (session.owner.clone(), session.name.clone());
    let fail = |e: String| note(&format!("{e}; force-push history not checked"));
    let viewer = match client.viewer() {
        Ok(v) => v,
        Err(e) => {
            fail(e);
            out.session = Some(session);
            return out;
        }
    };
    let log = match client.force_pushes(&slug.0, &slug.1, branch, budget.activity_pages) {
        Ok(v) => v,
        Err(e) => {
            fail(e);
            out.session = Some(session);
            return out;
        }
    };
    if log.truncated
        && let Some(oldest) = log.oldest()
        && since.is_none_or(|s| oldest > s)
    {
        note(&format!(
            "GitHub's force-push log was read back to {} ({} events); older force-pushes not checked{}",
            date(oldest),
            log.events.len(),
            if budget.activity_pages < Budget::DEEP.activity_pages {
                " (scan --github --deep reads further)"
            } else {
                ""
            }
        ));
    }
    let mut to_fetch = Vec::new();
    for e in log.events {
        // The user's own force-pushes (e.g. restoring the branch) are deliberate.
        if viewer.as_deref().is_some_and(|v| e.actor.eq_ignore_ascii_case(v)) || since.is_some_and(|s| e.at <= s) {
            continue;
        }
        let (Ok(before), Ok(after)) = (ObjectId::from_hex(e.before.as_bytes()), ObjectId::from_hex(e.after.as_bytes()))
        else {
            continue;
        };
        if before.is_null() {
            continue;
        }
        let contains = |tip: ObjectId| after == tip || repo.is_ancestor(after, tip).unwrap_or(false);
        // Only rewrites whose result is still in the history being pulled matter;
        // later force-pushes that undid them are superseded.
        let in_history = repo.has_object(after) && contains(new_tip);
        let already_in_head = in_history && head.is_some_and(contains);
        out.pushers.entry(before).or_insert(ForcePushInfo { by: e.actor.clone(), at: e.at, already_in_head });
        if !in_history || out.tips.iter().any(|(t, _)| *t == before) {
            continue;
        }
        if !repo.has_object(before) {
            to_fetch.push(before);
        }
        out.tips.push((before, TipSource::GitHub));
    }
    if fetch_missing && !to_fetch.is_empty() {
        let workdir = repo.workdir().unwrap_or_else(|| repo.git_dir().to_path_buf());
        if let Ok(git) = HardenedGit::new(&workdir) {
            for oid in to_fetch.iter().take(MAX_SHA_FETCHES) {
                // GitHub serves commits by full id even after a force-push.
                if git.fetch(remote, Some(&oid.to_string())).is_ok() {
                    out.fetched = true;
                }
            }
        }
    }
    if !common.json && !out.tips.is_empty() {
        eprintln!("git-shield: GitHub reports {} force-push(es) still in this history.", out.tips.len());
    }
    out.session = Some(session);
    out
}

/// Commits walked per activity event when attributing pushes.
const PUSH_WALK_LIMIT: usize = 5000;

/// Collect signature and GitHub evidence about `commits`.
/// `range` (`base`, `tip`) enables GitHub's compare API.
/// `require` applies the user's `[[signing]] require` policy (not on clone,
/// whose history predates any policy).
pub(crate) fn attest(
    repo: &GitRepo,
    commits: &[CommitInfo],
    range: Option<(&str, &str)>,
    known: &KnownTips,
    common: &Common,
    require: bool,
) -> Result<Option<Attestations>> {
    if commits.is_empty() {
        return Ok(None);
    }
    let policy = config::load()?.signing_for(&repo_ids(repo));
    if !require && policy.require {
        note("[[signing]] require is not applied to existing history; it applies to what later pulls bring in");
    }
    let mut a = Attestations { require_signed: require && policy.require, ..Default::default() };
    let mut cache = known.session.as_ref().map(|s| shield_github::cache::Cache::load(&s.owner, &s.name));
    if let Some(c) = &mut cache {
        c.set_keyring(&shield_git::signing::keyring_id());
    }
    if !common.no_verify_signatures {
        let allowed = policy
            .allowed_signers
            .or_else(|| doctor::git_global("gpg.ssh.allowedSignersFile").map(|p| config::expand_home(&p)));
        verify_local(repo, commits, allowed, known.budget, cache.as_mut(), &mut a);
    }
    if let (Some(s), Some(c)) = (&known.session, &mut cache) {
        github_attest(repo, commits, range, s, known, c, &mut a);
    }
    if let Some(c) = &mut cache {
        c.save();
    }
    Ok(Some(a))
}

fn verify_local(
    repo: &GitRepo,
    commits: &[CommitInfo],
    allowed: Option<PathBuf>,
    budget: Budget,
    mut cache: Option<&mut shield_github::cache::Cache>,
    a: &mut Attestations,
) {
    use shield_core::{SigCheck, SigFormat, SigStatus};
    use shield_github::cache::WebFlowVerdict;
    let signed: Vec<&CommitInfo> = commits.iter().filter(|c| c.signed).collect();
    if signed.is_empty() {
        return;
    }
    if signed.len() > budget.sig_checks {
        note(&format!("{} signed commits incoming; verified the newest {} locally", signed.len(), budget.sig_checks));
    }
    let web_flow = |c: &CommitInfo| c.committer_email.eq_ignore_ascii_case(shield_git::signing::GITHUB_EMAIL);
    let mut todo = Vec::new();
    for c in signed.into_iter().take(budget.sig_checks) {
        // GitHub's own signatures were checked before against the same bundled keyring.
        if web_flow(c)
            && let Some(v) = cache.as_deref().and_then(|k| k.webflow(&c.id))
        {
            let status =
                if v.good { SigStatus::Good { signer: v.detail.clone() } } else { SigStatus::Bad(v.detail.clone()) };
            a.local.insert(c.id.clone(), SigCheck { format: SigFormat::Gpg, status, web_flow: true });
        } else {
            todo.push(c);
        }
    }
    if todo.is_empty() {
        return;
    }
    // Extraction reads the object database (single-threaded); verification runs in parallel.
    let jobs: Vec<(&CommitInfo, shield_git::signing::SignedCommit)> = todo
        .into_iter()
        .filter_map(|c| {
            let id = ObjectId::from_hex(c.id.as_bytes()).ok()?;
            Some((c, repo.commit_signature(id).ok()??))
        })
        .collect();
    let v = match shield_git::signing::Verifier::new(allowed) {
        Ok(v) => v,
        Err(e) => {
            note(&format!("signature verification unavailable: {e}"));
            return;
        }
    };
    let results: Vec<(String, SigCheck)> =
        jobs.par_iter().map(|(c, s)| (c.id.clone(), v.verify(s, &c.committer_email))).collect();
    for (id, check) in results {
        if check.web_flow
            && check.format == SigFormat::Gpg
            && let Some(k) = cache.as_deref_mut()
        {
            match &check.status {
                SigStatus::Good { signer } => k.put_webflow(&id, WebFlowVerdict { good: true, detail: signer.clone() }),
                SigStatus::Bad(why) => k.put_webflow(&id, WebFlowVerdict { good: false, detail: why.clone() }),
                _ => {}
            }
        }
        a.local.insert(id, check);
    }
    for n in v.notes() {
        note(&n);
    }
}

fn remote_verification(rc: &shield_github::RemoteCommit) -> RemoteVerification {
    RemoteVerification {
        verified: rc.verified,
        reason: rc.reason.clone(),
        author_login: rc.author_login.clone(),
        committer_login: rc.committer_login.clone(),
    }
}

fn pr_state(st: shield_github::PullState) -> PrState {
    match st {
        shield_github::PullState::Merged { merge_commit_sha } => PrState::Merged { merge_commit_sha },
        shield_github::PullState::Open => PrState::Open,
        shield_github::PullState::ClosedUnmerged => PrState::ClosedUnmerged,
        shield_github::PullState::NotFound => PrState::NotFound,
    }
}

fn github_attest(
    repo: &GitRepo,
    commits: &[CommitInfo],
    range: Option<(&str, &str)>,
    s: &GhSession,
    known: &KnownTips,
    cache: &mut shield_github::cache::Cache,
    a: &mut Attestations,
) {
    use shield_github::PullState;
    let budget = known.budget;
    for c in commits {
        if let Some(rc) = cache.commit(&c.id) {
            a.github.insert(c.id.clone(), remote_verification(rc));
        }
    }
    // What is still unknown. GitHub's verdict on an unsigned commit is always
    // "unsigned", already known locally, so only signed commits are looked up.
    let signed: Vec<String> =
        commits.iter().filter(|c| c.signed && !a.github.contains_key(&c.id)).map(|c| c.id.clone()).collect();
    let take = signed.len().min(budget.remote_sigs);
    if take < signed.len() {
        note(&format!("{} signed commits; checked the newest {take} against GitHub", signed.len()));
    }
    let signed = &signed[..take];
    let mut nums: Vec<u64> = Vec::new();
    for n in commits.iter().filter_map(|c| shield_rules::claimed_pr(&c.summary)) {
        if !nums.contains(&n) {
            nums.push(n);
        }
    }
    if nums.len() > budget.prs {
        note(&format!("{} merged PRs claimed; checked the newest {} on GitHub", nums.len(), budget.prs));
        nums.truncate(budget.prs);
    }
    let uncached: Vec<u64> = nums.iter().copied().filter(|n| cache.pull(*n).is_none()).collect();
    // The first compare page proves the repository answers (a 404 elsewhere
    // then means "does not exist") and covers short ranges in one request.
    let compare = range.filter(|(b, t)| !cache.compared(b, t) && commits.iter().any(|c| !a.github.contains_key(&c.id)));

    // Independent requests: run them at the same time.
    let (cmp, sigs, prs) = std::thread::scope(|sc| {
        let cmp = compare.map(|(b, t)| sc.spawn(move || s.client.compare(&s.owner, &s.name, b, t, 1)));
        let sigs = (!signed.is_empty()).then(|| sc.spawn(|| s.client.commits_batch(&s.owner, &s.name, signed)));
        let prs = (!uncached.is_empty()).then(|| sc.spawn(|| s.client.pulls_batch(&s.owner, &s.name, &uncached)));
        fn join<T>(h: std::thread::ScopedJoinHandle<'_, T>) -> T {
            h.join().expect("GitHub request thread panicked")
        }
        (cmp.map(join), sigs.map(join), prs.map(join))
    });

    // GitHub answers 404 for anything in a repository the token cannot see, so a
    // missing PR only means "does not exist" once the repository answered.
    // None: not established this run (e.g. everything came from the cache).
    let mut repo_ok: Option<bool> = None;
    match cmp {
        Some(Ok((list, _))) => {
            let (b, t) = compare.expect("compare ran");
            cache.put_compared(b, t);
            repo_ok = Some(true);
            for rc in list {
                cache.put_commit(&rc);
                a.github.insert(rc.sha.clone(), remote_verification(&rc));
            }
        }
        Some(Err(e)) => {
            note(&format!("{e}; GitHub commit verification and pull requests not checked"));
            return;
        }
        None => {}
    }
    let found = match sigs {
        None => Ok(Vec::new()),
        Some(Ok(Some(v))) => {
            repo_ok = Some(true);
            Ok(v)
        }
        Some(Ok(None)) => {
            note("GitHub does not show this repository to your token; commits and pull requests not checked");
            return;
        }
        // GraphQL unavailable (e.g. some GitHub Enterprise setups): REST, one commit at a time.
        Some(Err(_)) => {
            let rest: Vec<&String> =
                signed.iter().filter(|id| !a.github.contains_key(*id)).take(REST_FALLBACK).collect();
            let got: Vec<_> = rest.par_iter().map(|sha| s.client.commit(&s.owner, &s.name, sha)).collect();
            got.into_iter().filter_map(|r| r.transpose()).collect::<Result<Vec<_>, String>>()
        }
    };
    match found {
        Ok(list) => {
            for rc in list {
                cache.put_commit(&rc);
                a.github.insert(rc.sha.clone(), remote_verification(&rc));
            }
        }
        Err(e) => note(&format!("{e}; signed commits not checked against GitHub")),
    }

    let mut answers: HashMap<u64, PullState> = match prs {
        None => HashMap::new(),
        Some(Ok(Some(m))) => m,
        Some(Ok(None)) => {
            note("GitHub does not show this repository to your token; pull requests not checked");
            HashMap::new()
        }
        Some(Err(_)) => rest_pulls(s, &uncached, repo_ok),
    };
    for (n, st) in &answers {
        cache.put_pull(*n, st);
    }
    for n in nums {
        let Some(state) = cache.pull(n).or_else(|| answers.remove(&n)) else { continue };
        a.prs.insert(n, pr_state(state));
    }

    if let Some(branch) = &known.branch {
        let base = range.and_then(|(b, _)| ObjectId::from_hex(b.as_bytes()).ok());
        attribute_pushes(repo, commits, base, s, branch, known, a);
    }
}

/// PR states one REST call at a time (GraphQL unavailable, e.g. some GHES).
fn rest_pulls(s: &GhSession, nums: &[u64], repo_ok: Option<bool>) -> HashMap<u64, shield_github::PullState> {
    if nums.len() > REST_FALLBACK {
        note(&format!("GitHub GraphQL unavailable; checked {REST_FALLBACK} of {} pull requests", nums.len()));
    }
    let nums = &nums[..nums.len().min(REST_FALLBACK)];
    let fetched: Vec<(u64, Result<shield_github::PullState, String>)> =
        nums.par_iter().map(|&n| (n, s.client.pull(&s.owner, &s.name, n))).collect();
    let mut answers = HashMap::new();
    let mut failed = false;
    for (n, r) in fetched {
        match r {
            Ok(st) => {
                answers.insert(n, st);
            }
            Err(e) if !failed => {
                failed = true;
                note(&format!("{e}; some pull request merge commits not checked"));
            }
            Err(_) => {}
        }
    }
    if repo_ok.is_none()
        && answers.values().any(|st| *st == shield_github::PullState::NotFound)
        && !s.client.repo_visible(&s.owner, &s.name)
    {
        note("GitHub does not show this repository to your token; pull requests not checked");
        answers.retain(|_, st| *st != shield_github::PullState::NotFound);
    }
    answers
}

/// For each incoming commit, the latest push event that brought it in. Reads
/// the activity log newest first and stops once every commit is explained, or
/// at a push that left the branch inside `base` (nothing incoming existed on
/// the branch then, so older pushes cannot have introduced it).
fn attribute_pushes(
    repo: &GitRepo,
    commits: &[CommitInfo],
    base: Option<ObjectId>,
    s: &GhSession,
    branch: &str,
    known: &KnownTips,
    a: &mut Attestations,
) {
    let incoming: HashSet<&str> = commits.iter().map(|c| c.id.as_str()).collect();
    let since = known.since;
    let mut found: HashMap<String, PushedBy> = HashMap::new();
    let mut done = 0;
    let mut reached_base = false;
    let log = s.client.activity(&s.owner, &s.name, branch, None, since, known.budget.activity_pages, |events| {
        for e in &events[done..] {
            if since.is_some_and(|t| e.at <= t) {
                continue;
            }
            let Ok(after) = ObjectId::from_hex(e.after.as_bytes()) else { continue };
            if after.is_null() || !repo.has_object(after) {
                continue;
            }
            if base.is_some_and(|b| after == b || repo.is_ancestor(after, b).unwrap_or(false)) {
                reached_base = true;
                break;
            }
            let hide = match ObjectId::from_hex(e.before.as_bytes()) {
                Ok(b) if repo.has_object(b) => b,
                // Branch creation (copies commits that already exist elsewhere), or an
                // unknown starting point: cannot tell which commits this push added.
                _ => continue,
            };
            for id in repo.commit_ids(after, Some(hide), PUSH_WALK_LIMIT).unwrap_or_default() {
                let h = id.to_string();
                if incoming.contains(h.as_str()) {
                    // Newest first: the push that last brought the commit in.
                    found.entry(h).or_insert_with(|| PushedBy {
                        login: e.actor.clone(),
                        kind: e.kind.clone(),
                        at: e.at,
                    });
                }
            }
        }
        done = events.len();
        reached_base || found.len() == incoming.len()
    });
    match log {
        Ok(log) => {
            if log.truncated
                && found.len() < incoming.len()
                && let Some(oldest) = log.oldest()
            {
                note(&format!(
                    "GitHub activity read back to {} ({} events); older pushes not attributed",
                    date(oldest),
                    log.events.len()
                ));
            }
            a.pushes.extend(found);
        }
        Err(e) => note(&format!("{e}; push history not checked")),
    }
}

/// Remote and branch whose GitHub history explains a range ending at `to`
/// that is not itself a remote-tracking ref: `--github-branch`, else a remote
/// branch whose tip is `to`, else the remote's default branch when it contains
/// `to`. Feature branches are never guessed: they usually contain all of the
/// integration branch, and their creation would claim every commit.
fn history_branch(repo: &GitRepo, to: ObjectId, given: Option<&str>, common: &Common) -> Option<(String, String)> {
    let remote = repo.upstream().ok().map(|u| u.remote).unwrap_or_else(|| "origin".into());
    if let Some(b) = given {
        return Some((remote, b.to_string()));
    }
    let branches = repo.remote_branches(&remote);
    let found = branches.iter().find(|(_, tip)| *tip == to).map(|(b, _)| b.clone()).or_else(|| {
        let def = repo.remote_default_branch(&remote)?;
        let tip = branches.iter().find(|(b, _)| *b == def)?.1;
        (tip == to || repo.is_ancestor(to, tip).unwrap_or(false)).then_some(def)
    });
    match found {
        Some(b) => {
            if !common.json {
                eprintln!("git-shield: using the GitHub push history of {remote}/{b}");
            }
            Some((remote, b))
        }
        None => {
            note("pass --github-branch BRANCH to also check who pushed these commits and the force-push log");
            None
        }
    }
}

static DETECTORS: std::sync::OnceLock<Vec<Box<dyn shield_core::Detector>>> = std::sync::OnceLock::new();

/// Built-in detectors plus the user's YARA rules (ADR 0009). A rule that does
/// not compile stops the run: silently skipping it would hide that it is off.
fn load_detectors() -> Result<()> {
    let dir = shield_rules::rules_dir();
    #[cfg_attr(not(feature = "yara"), allow(unused_mut))]
    let mut extra: Vec<Box<dyn shield_core::Detector>> = Vec::new();
    if let Some(dir) = &dir {
        #[cfg(feature = "yara")]
        if let Some(d) = shield_rules::yara::compile_dir(dir).map_err(anyhow::Error::msg)? {
            extra.push(Box::new(d));
        }
        #[cfg(not(feature = "yara"))]
        {
            let n = shield_rules::rule_files(dir).map_err(anyhow::Error::msg)?.len();
            if n > 0 {
                note(&format!("this build has no YARA support; {n} rule file(s) in {} are not used", dir.display()));
            }
        }
    }
    let _ = DETECTORS.set(shield_rules::builtin_with(extra));
    Ok(())
}

fn scan(ctx: &ScanContext) -> Report {
    shield_core::run(DETECTORS.get_or_init(shield_rules::builtin), ctx)
}

/// Config keys the hardened runner already overrides on the command line.
const NEUTRALISED: &[&str] = &["core.fsmonitor", "core.hookspath", "core.pager", "diff.external", "protocol.ext.allow"];

/// Refuse to spawn git when the local config would make it run attacker code.
///
/// `fetch` only needs Critical keys to be absent. When git will also touch the
/// working tree (`pull`), High keys that fire on checkout/merge (filters,
/// merge drivers, gpg programs) block as well, unless already neutralised.
fn preflight(repo: &GitRepo, allow: bool, worktree: bool, common: &Common) -> Result<()> {
    let ctx = ScanContext {
        label: "local git config".into(),
        local: Some(shield_git::read_local_state(repo)?),
        ..Default::default()
    };
    let report = scan(&ctx);
    let refuse: Vec<_> = report
        .findings
        .iter()
        .filter(|f| match f.severity {
            Severity::Critical => true,
            Severity::High if worktree && f.rule == "git.local-config" => {
                let key = f.anchor.as_deref().and_then(|a| a.split_once('=')).map(|(k, _)| k.to_ascii_lowercase());
                !key.is_some_and(|k| NEUTRALISED.contains(&k.as_str()))
            }
            _ => false,
        })
        .collect();
    if refuse.is_empty() || allow {
        return Ok(());
    }
    eprint!("{}", shield_report::terminal(&report, &HashSet::new(), color(common), common.verbose));
    bail!(
        "local git config contains settings that make git execute programs ({}); refusing to run git. \
         Remove them or pass --allow-unsafe-config.",
        refuse.iter().map(|f| f.id.0.as_str()).collect::<Vec<_>>().join(", ")
    )
}

/// Returns (from, to, B spec, label).
fn resolve_range(repo: &GitRepo, range: Option<&str>) -> Result<(ObjectId, ObjectId, String, String)> {
    let (a, b) = match range {
        Some(r) if r.contains("...") => {
            let (a, b) = r.split_once("...").unwrap();
            (if a.is_empty() { "HEAD" } else { a }.to_string(), b.to_string())
        }
        Some(r) if r.contains("..") => {
            let (a, b) = r.split_once("..").unwrap();
            (if a.is_empty() { "HEAD" } else { a }.to_string(), if b.is_empty() { "HEAD" } else { b }.to_string())
        }
        Some(r) => ("HEAD".to_string(), r.to_string()),
        None => ("HEAD".to_string(), repo.upstream()?.tracking_ref),
    };
    let from = repo.resolve(&a)?;
    let to = repo.resolve(&b)?;
    let label = format!("{a}..{b}");
    Ok((from, to, b, label))
}

/// Accepted ids: `--accept`, the trust store, and the user allowlist.
fn accepted(
    common: &Common,
    store: Option<&TrustStore>,
    report: &Report,
    repo: Option<&GitRepo>,
) -> Result<HashSet<String>> {
    let mut out: HashSet<String> = common.accept.iter().cloned().collect();
    if let Some(store) = store {
        out.extend(store.accepted_ids().map(str::to_string));
    }
    let cfg = config::load()?;
    if !cfg.allow.is_empty() {
        let ids_for = repo.map(repo_ids).unwrap_or_default();
        let (ids, warnings) = cfg.accepted(&report.findings, &ids_for);
        for w in warnings {
            note(&w);
        }
        out.extend(ids.into_iter().map(str::to_string));
    }
    Ok(out)
}

/// Names this repository goes by, for `repo =` allowlist globs:
/// `github.com/OWNER/NAME` for GitHub remotes, plus every remote URL as-is.
fn repo_ids(repo: &GitRepo) -> Vec<String> {
    let mut remotes = vec!["origin".to_string()];
    if let Ok(up) = repo.upstream() {
        remotes.insert(0, up.remote);
    }
    let mut ids = Vec::new();
    for r in remotes {
        let Some(url) = repo.remote_url(&r) else { continue };
        if let Some((o, n)) = shield_github::repo_slug(&url) {
            ids.push(format!("github.com/{o}/{n}"));
        }
        ids.push(url);
    }
    ids
}

fn color(common: &Common) -> bool {
    !common.no_color && !common.json && std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

fn emit(report: &Report, accepted: &HashSet<String>, common: &Common) -> u8 {
    if common.json {
        println!("{}", shield_report::json(report, accepted));
    } else {
        print!("{}", shield_report::terminal(report, accepted, color(common), common.verbose));
    }
    if let Some(p) = &common.sarif {
        let text = shield_report::sarif(report, accepted, env!("CARGO_PKG_VERSION"));
        if let Err(e) = std::fs::write(p, text) {
            eprintln!("git-shield: error: writing {}: {e}", p.display());
            return 3;
        }
    }
    report.exit_code(accepted) as u8
}

//! `git-shield`: inspect incoming git changes before they touch your working tree.
//!
//! Installed on PATH as `git-shield`, it is also available as `git shield`.

mod audit;
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
    match cli.command {
        Command::Scan { range, previous_tip, github, common } => {
            let repo = GitRepo::discover(&common.repo)?;
            let store = TrustStore::open(&repo)?;
            let (from, to, b, label) = resolve_range(&repo, range.as_deref())?;
            let given =
                previous_tip.iter().map(|r| Ok((repo.resolve(r)?, TipSource::Given))).collect::<Result<Vec<_>>>()?;
            let full = repo.full_ref_name(&b);
            let mut gh = KnownTips::default();
            if github {
                match full.as_deref().and_then(|r| r.strip_prefix("refs/remotes/")).and_then(|r| r.split_once('/')) {
                    Some((remote, branch)) => {
                        gh = github_tips(
                            &repo,
                            &store,
                            full.as_deref().unwrap(),
                            remote,
                            branch,
                            to,
                            Some(from),
                            false,
                            &common,
                        );
                    }
                    // Not a remote-tracking ref: no force-push history, but commits and PRs can still be checked.
                    None => gh.session = gh_session(&repo, None, &common),
                }
            }
            gh.tips.splice(0..0, given);
            // Provenance needs a ref; with only --previous-tip, use the range end itself.
            let ref_name = full.or_else(|| (!gh.tips.is_empty()).then(|| b.clone()));
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
        Command::Doctor { json } => doctor::run(json),
        Command::Install { shell, rc, write } => install::install(shell.as_deref(), rc, write),
        Command::Uninstall { shell, rc } => install::uninstall(shell.as_deref(), rc),
        Command::Clone { url, dir, branch, reason, common } => {
            worktree::clone(&url, dir, branch.as_deref(), reason, &common)
        }
        Command::Checkout { target, reason, allow_unsafe_config, common } => {
            worktree::checkout(&target, reason, allow_unsafe_config, &common)
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
        github_tips(&repo, &store, &tracking, &remote, &branch, tip, repo.resolve("HEAD").ok(), true, &common)
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
    attest(repo, &mut ctx, known, common)?;
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
}

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
    common: &Common,
) -> KnownTips {
    let mut out = KnownTips {
        branch: Some(branch.to_string()),
        since: store.trusted_tip(ref_name).map(|t| t.at),
        ..Default::default()
    };
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
    let events = match client.force_pushes(&slug.0, &slug.1, branch) {
        Ok(v) => v,
        Err(e) => {
            fail(e);
            out.session = Some(session);
            return out;
        }
    };
    let since = store.trusted_tip(ref_name).map(|t| t.at);
    let mut to_fetch = Vec::new();
    for e in events {
        // The user's own force-pushes (e.g. restoring the branch) are deliberate.
        if e.actor.eq_ignore_ascii_case(&viewer) || since.is_some_and(|s| e.at <= s) {
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

/// At most this many signed incoming commits are verified locally per scan.
const MAX_SIG_CHECKS: usize = 300;
/// At most this many distinct "Merge pull request #N" numbers are looked up per scan.
const MAX_PR_LOOKUPS: usize = 100;
/// Commits walked per activity event when attributing pushes.
const PUSH_WALK_LIMIT: usize = 5000;

/// Collect signature and GitHub evidence about the incoming commits.
fn attest(repo: &GitRepo, ctx: &mut ScanContext, known: &KnownTips, common: &Common) -> Result<()> {
    if ctx.commits.is_empty() {
        return Ok(());
    }
    let policy = config::load()?.signing_for(&repo_ids(repo));
    let mut a = Attestations { require_signed: policy.require, ..Default::default() };
    if !common.no_verify_signatures {
        let allowed = policy
            .allowed_signers
            .or_else(|| doctor::git_global("gpg.ssh.allowedSignersFile").map(|p| config::expand_home(&p)));
        verify_local(repo, &ctx.commits, allowed, &mut a);
    }
    if let Some(s) = &known.session {
        github_attest(repo, ctx, s, known, &mut a);
    }
    ctx.attest = Some(a);
    Ok(())
}

fn verify_local(repo: &GitRepo, commits: &[CommitInfo], allowed: Option<PathBuf>, a: &mut Attestations) {
    let signed: Vec<&CommitInfo> = commits.iter().filter(|c| c.signed).collect();
    if signed.is_empty() {
        return;
    }
    if signed.len() > MAX_SIG_CHECKS {
        note(&format!("{} signed commits incoming; verified the newest {MAX_SIG_CHECKS} locally", signed.len()));
    }
    // Extraction reads the object database (single-threaded); verification runs in parallel.
    let jobs: Vec<(&CommitInfo, shield_git::signing::SignedCommit)> = signed
        .into_iter()
        .take(MAX_SIG_CHECKS)
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
    let results: Vec<(String, shield_core::SigCheck)> =
        jobs.par_iter().map(|(c, s)| (c.id.clone(), v.verify(s, &c.committer_email))).collect();
    a.local.extend(results);
    for n in v.notes() {
        note(&n);
    }
}

fn github_attest(repo: &GitRepo, ctx: &ScanContext, s: &GhSession, known: &KnownTips, a: &mut Attestations) {
    let mut cache = shield_github::cache::Cache::load(&s.owner, &s.name);
    let mut fresh: HashMap<String, shield_github::RemoteCommit> = HashMap::new();
    // GitHub answers 404 for anything in a repository the token cannot see, so a
    // missing PR only means "does not exist" once the repository answered.
    // None: not established this run (e.g. compare answered from the cache).
    let mut repo_ok: Option<bool> = None;
    if let (Some(base), Some(tip)) = (&ctx.base, &ctx.tip)
        && !cache.compared(base, tip)
        && ctx.commits.iter().any(|c| cache.commit(&c.id).is_none())
    {
        match s.client.compare(&s.owner, &s.name, base, tip) {
            Ok((list, total)) => {
                cache.put_compared(base, tip);
                repo_ok = Some(true);
                if total > list.len() {
                    note(&format!(
                        "GitHub listed {} of {total} commits; the rest were not checked against GitHub",
                        list.len()
                    ));
                }
                for rc in list {
                    cache.put_commit(&rc);
                    fresh.insert(rc.sha.clone(), rc);
                }
            }
            Err(e) => {
                repo_ok = Some(false);
                note(&format!("{e}; GitHub commit verification and pull requests not checked"));
            }
        }
    }
    for c in &ctx.commits {
        if let Some(rc) = fresh.get(&c.id).or_else(|| cache.commit(&c.id)) {
            a.github.insert(
                c.id.clone(),
                RemoteVerification {
                    verified: rc.verified,
                    reason: rc.reason.clone(),
                    author_login: rc.author_login.clone(),
                    committer_login: rc.committer_login.clone(),
                },
            );
        }
    }

    let mut nums: Vec<u64> = Vec::new();
    for n in ctx.commits.iter().filter_map(|c| shield_rules::claimed_pr(&c.summary)) {
        if !nums.contains(&n) {
            nums.push(n);
        }
    }
    if repo_ok == Some(false) {
        nums.clear();
    }
    if nums.len() > MAX_PR_LOOKUPS {
        note(&format!("{} merged PRs claimed; checked the newest {MAX_PR_LOOKUPS} on GitHub", nums.len()));
        nums.truncate(MAX_PR_LOOKUPS);
    }
    // Uncached lookups run in parallel; the first error stops further use of the answers.
    let uncached: Vec<u64> = nums.iter().copied().filter(|n| cache.pull(*n).is_none()).collect();
    let fetched: Vec<(u64, Result<shield_github::PullState, String>)> =
        uncached.par_iter().map(|&n| (n, s.client.pull(&s.owner, &s.name, n))).collect();
    let mut answers: HashMap<u64, shield_github::PullState> = HashMap::new();
    let mut failed = false;
    for (n, r) in fetched {
        match r {
            Ok(st) => {
                cache.put_pull(n, &st);
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
    for n in nums {
        let Some(state) = cache.pull(n).or_else(|| answers.remove(&n)) else { continue };
        let st = match state {
            shield_github::PullState::Merged { merge_commit_sha } => PrState::Merged { merge_commit_sha },
            shield_github::PullState::Open => PrState::Open,
            shield_github::PullState::ClosedUnmerged => PrState::ClosedUnmerged,
            shield_github::PullState::NotFound => PrState::NotFound,
        };
        a.prs.insert(n, st);
    }
    cache.save();

    if let Some(branch) = &known.branch {
        match s.client.activity(&s.owner, &s.name, branch, None, known.since) {
            Ok(events) => attribute_pushes(repo, ctx, &events, known.since, a),
            Err(e) => note(&format!("{e}; push history not checked")),
        }
    }
}

/// For each incoming commit, the oldest push event that introduced it.
fn attribute_pushes(
    repo: &GitRepo,
    ctx: &ScanContext,
    events: &[shield_github::Push],
    since: Option<i64>,
    a: &mut Attestations,
) {
    let incoming: HashSet<&str> = ctx.commits.iter().map(|c| c.id.as_str()).collect();
    for e in events.iter().rev() {
        if since.is_some_and(|s| e.at <= s) {
            continue;
        }
        let Ok(after) = ObjectId::from_hex(e.after.as_bytes()) else { continue };
        if after.is_null() || !repo.has_object(after) {
            continue;
        }
        let hide = match ObjectId::from_hex(e.before.as_bytes()) {
            Ok(b) if b.is_null() => None,
            Ok(b) if repo.has_object(b) => Some(b),
            // Unknown starting point: cannot tell which commits this push added.
            _ => continue,
        };
        for id in repo.commit_ids(after, hide, PUSH_WALK_LIMIT).unwrap_or_default() {
            let h = id.to_string();
            if incoming.contains(h.as_str()) {
                a.pushes.entry(h).or_insert_with(|| PushedBy {
                    login: e.actor.clone(),
                    kind: e.kind.clone(),
                    at: e.at,
                });
            }
        }
        if a.pushes.len() == incoming.len() {
            break;
        }
    }
}

fn scan(ctx: &ScanContext) -> Report {
    shield_core::run(&shield_rules::builtin(), ctx)
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
    report.exit_code(accepted) as u8
}

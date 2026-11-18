//! `git-shield`: inspect incoming git changes before they touch your working tree.
//!
//! Installed on PATH as `git-shield`, it is also available as `git shield`.

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use shield_core::{Report, ScanContext, Severity, TipSource};
use shield_git::trust::TrustStore;
use shield_git::{GitRepo, ObjectId, ProvenanceInput, hardened::HardenedGit};
use std::collections::HashSet;
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
        #[command(flatten)]
        common: Common,
    },
    /// Show or change what git-shield remembers for this repository
    /// (accepted findings and the last tip pulled per ref).
    Trust {
        #[command(subcommand)]
        action: TrustAction,
    },
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
        Command::Scan { range, previous_tip, common } => {
            let repo = GitRepo::discover(&common.repo)?;
            let store = TrustStore::open(&repo)?;
            let (from, to, b, label) = resolve_range(&repo, range.as_deref())?;
            let given =
                previous_tip.iter().map(|r| Ok((repo.resolve(r)?, TipSource::Given))).collect::<Result<Vec<_>>>()?;
            // Provenance needs a ref; with only --previous-tip, use the range end itself.
            let ref_name = repo.full_ref_name(&b).or_else(|| (!given.is_empty()).then(|| b.clone()));
            let ctx = build_context(&repo, &store, from, to, label, ref_name.as_deref(), &given)?;
            let report = scan(&ctx);
            Ok(emit(&report, &accepted(&common, &store), &common))
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
            let from = repo.resolve("HEAD")?;
            let to = repo.resolve(&tracking).with_context(|| format!("remote-tracking ref {tracking} not found"))?;
            let extra: Vec<_> = prefetch.map(|p| (p, TipSource::PreFetch)).into_iter().collect();
            let ctx =
                build_context(&repo, &store, from, to, format!("HEAD..{remote}/{branch}"), Some(&tracking), &extra)?;
            Ok(emit(&scan(&ctx), &accepted(&common, &store), &common))
        }
        Command::Pull { target, rebase, merge, reason, common } => pull(target, rebase, merge, reason, common),
        Command::Trust { action } => trust(action),
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

/// `YYYY-MM-DD` (UTC) from unix seconds.
fn date(secs: i64) -> String {
    // Civil-from-days (Howard Hinnant), avoiding a date crate for one line of output.
    let z = secs.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
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
    let head = repo.resolve("HEAD")?;
    let tip = repo.resolve(&tracking).with_context(|| format!("remote-tracking ref {tracking} not found"))?;
    let extra: Vec<_> = prefetch.map(|p| (p, TipSource::PreFetch)).into_iter().collect();
    let ctx = build_context(&repo, &store, head, tip, format!("HEAD..{remote}/{branch}"), Some(&tracking), &extra)?;
    let report = scan(&ctx);
    let mut accepted = accepted(&common, &store);
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

    // Decide.
    let mut newly_accepted: Vec<String> =
        common.accept.iter().filter(|id| report.findings.iter().any(|f| &f.id.0 == *id)).cloned().collect();
    let blocking: Vec<String> = report.blocking(&accepted).map(|f| f.id.0.clone()).collect();
    let mut reason = reason;
    if !blocking.is_empty() {
        if !interactive(&common) {
            eprintln!("git-shield: pull blocked; nothing was merged.");
            return Ok(2);
        }
        let ok = dialoguer::Confirm::new()
            .with_prompt(format!("Accept {} blocking finding(s) and pull anyway?", blocking.len()))
            .default(false)
            .interact()
            .unwrap_or(false);
        if !ok {
            eprintln!("git-shield: pull aborted; nothing was merged.");
            return Ok(2);
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

    let reason = reason.filter(|r| !r.trim().is_empty()).unwrap_or_else(|| "accepted via --accept".into());
    let t = now();
    let tip_hex = tip.to_string();
    for id in &newly_accepted {
        store.accept(id, &reason, Some(&tip_hex), t);
    }
    store.set_tip(&tracking, &tip_hex, t);
    store.save().with_context(|| format!("writing trust store {}", store.path().display()))?;

    Ok(report.exit_code(&accepted) as u8)
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
fn build_context(
    repo: &GitRepo,
    store: &TrustStore,
    from: ObjectId,
    to: ObjectId,
    label: String,
    ref_name: Option<&str>,
    known_tips: &[(ObjectId, TipSource)],
) -> Result<ScanContext> {
    let mut ctx = repo.incoming(from, to, label)?;
    let Some(ref_name) = ref_name else { return Ok(ctx) };
    let t = now();
    let mut extra = known_tips.to_vec();
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
        reflog_since: trusted.map_or(t - shield_git::REFLOG_WINDOW_SECS, |tt| tt.at),
        now: t,
    };
    ctx.provenance = Some(repo.provenance(&input)?);
    Ok(ctx)
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

fn accepted(common: &Common, store: &TrustStore) -> HashSet<String> {
    common.accept.iter().cloned().chain(store.accepted_ids().map(str::to_string)).collect()
}

fn color(common: &Common) -> bool {
    !common.no_color && !common.json && std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

fn emit(report: &Report, accepted: &HashSet<String>, common: &Common) -> u8 {
    if common.json {
        println!("{}", shield_report::json(report));
    } else {
        print!("{}", shield_report::terminal(report, accepted, color(common), common.verbose));
    }
    report.exit_code(accepted) as u8
}

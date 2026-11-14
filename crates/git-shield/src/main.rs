//! `git-shield`: inspect incoming git changes before they touch your working tree.
//!
//! Installed on PATH as `git-shield`, it is also available as `git shield`.

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use shield_core::{Report, ScanContext, Severity};
use shield_git::{GitRepo, hardened::HardenedGit};
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
        #[command(flatten)]
        common: Common,
    },
    /// Fetch (hardened, objects only) and scan what a pull would bring in. Never merges.
    Check {
        /// Remote name; defaults to the current branch's upstream remote.
        remote: Option<String>,
        /// Remote branch; defaults to the current branch's upstream branch.
        branch: Option<String>,
        /// Skip the fetch and scan the existing remote-tracking ref.
        #[arg(long)]
        no_fetch: bool,
        /// Fetch even if the local git config contains critical execution settings.
        #[arg(long)]
        allow_unsafe_config: bool,
        #[command(flatten)]
        common: Common,
    },
}

#[derive(Args)]
struct Common {
    /// Repository path (defaults to the current directory).
    #[arg(long, short = 'C', default_value = ".")]
    repo: PathBuf,
    /// Emit the report as JSON.
    #[arg(long)]
    json: bool,
    /// Also show info-level findings.
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

fn run(cli: Cli) -> Result<u8> {
    match cli.command {
        Command::Scan { range, common } => {
            let repo = GitRepo::discover(&common.repo)?;
            let (from, to, label) = resolve_range(&repo, range.as_deref())?;
            let ctx = repo.incoming(from, to, label)?;
            let report = scan(&ctx);
            Ok(emit(&report, &common))
        }
        Command::Check { remote, branch, no_fetch, allow_unsafe_config, common } => {
            let repo = GitRepo::discover(&common.repo)?;
            let (remote, branch) = match (remote, branch) {
                (Some(r), Some(b)) => (r, b),
                (r, b) => {
                    let up = repo.upstream()?;
                    (r.unwrap_or(up.remote), b.unwrap_or(up.branch))
                }
            };

            if !no_fetch {
                preflight(&repo, allow_unsafe_config, &common)?;
                let workdir = repo.workdir().unwrap_or_else(|| repo.git_dir().to_path_buf());
                if !common.json {
                    eprintln!("git-shield: fetching {remote} {branch} (hardened, no checkout)…");
                }
                HardenedGit::new(&workdir)?.fetch(&remote, Some(&branch))?;
            }

            // Re-open so refs updated by the fetch are visible.
            let repo = GitRepo::discover(&common.repo)?;
            let tracking = format!("refs/remotes/{remote}/{branch}");
            let from = repo.resolve("HEAD")?;
            let to = repo.resolve(&tracking).with_context(|| format!("remote-tracking ref {tracking} not found"))?;
            let ctx = repo.incoming(from, to, format!("HEAD..{remote}/{branch}"))?;
            Ok(emit(&scan(&ctx), &common))
        }
    }
}

fn scan(ctx: &ScanContext) -> Report {
    shield_core::run(&shield_rules::builtin(), ctx)
}

/// Refuse to spawn git when the local config would make it run attacker code.
fn preflight(repo: &GitRepo, allow: bool, common: &Common) -> Result<()> {
    let ctx = ScanContext {
        label: "local git config".into(),
        local: Some(shield_git::read_local_state(repo)?),
        ..Default::default()
    };
    let report = scan(&ctx);
    let critical: Vec<_> = report.findings.iter().filter(|f| f.severity == Severity::Critical).collect();
    if critical.is_empty() || allow {
        return Ok(());
    }
    eprint!("{}", shield_report::terminal(&report, &HashSet::new(), color(common), common.verbose));
    bail!(
        "local git config contains settings that make git execute programs ({}); refusing to run git. \
         Remove them or pass --allow-unsafe-config.",
        critical.iter().map(|f| f.id.0.as_str()).collect::<Vec<_>>().join(", ")
    )
}

fn resolve_range(repo: &GitRepo, range: Option<&str>) -> Result<(shield_git::ObjectId, shield_git::ObjectId, String)> {
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
    Ok((from, to, format!("{a}..{b}")))
}

fn color(common: &Common) -> bool {
    !common.no_color && !common.json && std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

fn emit(report: &Report, common: &Common) -> u8 {
    let accepted: HashSet<String> = common.accept.iter().cloned().collect();
    if common.json {
        println!("{}", shield_report::json(report));
    } else {
        print!("{}", shield_report::terminal(report, &accepted, color(common), common.verbose));
    }
    report.exit_code(&accepted) as u8
}

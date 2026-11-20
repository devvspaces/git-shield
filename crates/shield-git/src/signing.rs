//! Cryptographic verification of commit signatures (GPG and SSH).
//!
//! The signature and the exact signed bytes are extracted in-process by gix;
//! `gpgv`, `gpg` and `ssh-keygen` are then run as plain subprocesses from an
//! empty temp directory, with a scrubbed environment and a timeout. Nothing
//! from the repository's config (`gpg.program`, `gpg.ssh.program`, ...) is
//! consulted, so a repository cannot substitute its own "verifier".
//!
//! Commits that claim GitHub as committer are checked against GitHub's
//! published web-flow keys, bundled in `data/github-web-flow.gpg` (ADR 0007),
//! in an empty GNUPGHOME, so the user's keyring cannot vouch for them.

use crate::{GitRepo, Result, git_err};
use gix::ObjectId;
use shield_core::{SigCheck, SigFormat, SigStatus};
use std::collections::BTreeSet;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// GitHub's web-flow signing keys (from <https://github.com/web-flow.gpg>), dearmored.
const WEB_FLOW_KEYRING: &[u8] = include_bytes!("../data/github-web-flow.gpg");
const TIMEOUT: Duration = Duration::from_secs(5);
/// Committer email GitHub uses for merges and web edits.
pub const GITHUB_EMAIL: &str = "noreply@github.com";

/// A commit's signature and the bytes it signs.
pub struct SignedCommit {
    pub signature: Vec<u8>,
    pub payload: Vec<u8>,
    pub format: SigFormat,
}

pub fn format_of(sig: &[u8]) -> SigFormat {
    let s = String::from_utf8_lossy(sig);
    let s = s.trim_start();
    if s.starts_with("-----BEGIN PGP SIGNATURE-----") {
        SigFormat::Gpg
    } else if s.starts_with("-----BEGIN SSH SIGNATURE-----") {
        SigFormat::Ssh
    } else if s.starts_with("-----BEGIN SIGNED MESSAGE-----") || s.starts_with("-----BEGIN CERTIFICATE-----") {
        SigFormat::X509
    } else {
        SigFormat::Unknown
    }
}

/// Split a raw commit object into signature and signed payload.
pub fn split_signature(raw: &[u8], kind: gix::hash::Kind) -> Option<SignedCommit> {
    let (sig, signed) = gix::objs::CommitRefIter::signature(raw, kind).ok()??;
    let mut signature = sig.to_vec();
    if !signature.ends_with(b"\n") {
        signature.push(b'\n');
    }
    Some(SignedCommit { format: format_of(&signature), signature, payload: signed.to_bstring().into() })
}

impl GitRepo {
    /// The signature of commit `id`, if it has one.
    pub fn commit_signature(&self, id: ObjectId) -> Result<Option<SignedCommit>> {
        let commit = self.repo.find_commit(id).map_err(git_err)?;
        Ok(split_signature(&commit.data, self.repo.object_hash()))
    }
}

/// Runs the verifiers. Create one per scan; `notes` collects one line per
/// missing tool or other reason checks were skipped.
pub struct Verifier {
    tmp: tempfile::TempDir,
    keyring: PathBuf,
    allowed_signers: Option<PathBuf>,
    pub notes: BTreeSet<String>,
}

impl Verifier {
    pub fn new(allowed_signers: Option<PathBuf>) -> Result<Self> {
        let tmp = tempfile::tempdir()?;
        let keyring = tmp.path().join("web-flow.gpg");
        std::fs::write(&keyring, WEB_FLOW_KEYRING)?;
        std::fs::create_dir(tmp.path().join("gnupg"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(tmp.path().join("gnupg"), std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Verifier { tmp, keyring, allowed_signers, notes: BTreeSet::new() })
    }

    /// Verify one signature. `committer_email` is the identity an SSH
    /// signature must belong to (allowed-signers principal).
    pub fn verify(&mut self, s: &SignedCommit, committer_email: &str) -> SigCheck {
        let web_flow = committer_email.eq_ignore_ascii_case(GITHUB_EMAIL);
        let status = match (s.format, web_flow) {
            (SigFormat::Gpg, true) => self.gpgv_web_flow(s),
            // GitHub only signs with its GPG key.
            (_, true) => SigStatus::Bad("GitHub signs its commits with GPG, this signature is not GPG".into()),
            (SigFormat::Gpg, false) => self.gpg_user(s),
            (SigFormat::Ssh, false) => self.ssh(s, committer_email),
            (SigFormat::X509, false) => SigStatus::Unchecked("X.509 signatures are not checked".into()),
            (SigFormat::Unknown, false) => SigStatus::Bad("unrecognised signature format".into()),
        };
        SigCheck { format: s.format, status, web_flow }
    }

    fn files(&self, s: &SignedCommit) -> Option<(PathBuf, PathBuf)> {
        let sig = self.tmp.path().join("sig");
        let payload = self.tmp.path().join("payload");
        std::fs::write(&sig, &s.signature).ok()?;
        std::fs::write(&payload, &s.payload).ok()?;
        Some((sig, payload))
    }

    fn gpgv_web_flow(&mut self, s: &SignedCommit) -> SigStatus {
        let Some((sig, payload)) = self.files(s) else { return SigStatus::Unchecked("temp files".into()) };
        let mut cmd = Command::new("gpgv");
        cmd.arg("--status-fd").arg("1").arg("--keyring").arg(&self.keyring).arg(&sig).arg(&payload);
        cmd.env("GNUPGHOME", self.tmp.path().join("gnupg"));
        match self.run(cmd, None, "gpgv") {
            Some((_, out, _)) => gpg_status(&out),
            None => SigStatus::Unchecked("gpgv unavailable".into()),
        }
    }

    fn gpg_user(&mut self, s: &SignedCommit) -> SigStatus {
        let Some((sig, payload)) = self.files(s) else { return SigStatus::Unchecked("temp files".into()) };
        let mut cmd = Command::new("gpg");
        cmd.args(["--batch", "--no-tty", "--status-fd", "1", "--no-auto-key-retrieve", "--verify"]);
        cmd.arg(&sig).arg(&payload);
        match self.run(cmd, None, "gpg") {
            Some((_, out, _)) => gpg_status(&out),
            None => SigStatus::Unchecked("gpg unavailable".into()),
        }
    }

    fn ssh(&mut self, s: &SignedCommit, email: &str) -> SigStatus {
        let Some((sig, payload)) = self.files(s) else { return SigStatus::Unchecked("temp files".into()) };
        let intact = {
            let mut cmd = Command::new("ssh-keygen");
            cmd.args(["-Y", "check-novalidate", "-n", "git", "-s"]).arg(&sig);
            match self.run(cmd, Some(&payload), "ssh-keygen") {
                Some((true, _, _)) => true,
                Some((false, out, err)) => {
                    let msg = format!("{out}{err}");
                    if msg.contains("incorrect signature") || msg.contains("verification failed") {
                        return SigStatus::Bad("the SSH signature does not match the commit".into());
                    }
                    return SigStatus::Unchecked(first_line(&msg));
                }
                None => return SigStatus::Unchecked("ssh-keygen unavailable".into()),
            }
        };
        let Some(allowed) = self.allowed_signers.clone() else {
            return if intact { SigStatus::Intact } else { SigStatus::Unchecked("ssh".into()) };
        };
        let mut cmd = Command::new("ssh-keygen");
        cmd.args(["-Y", "verify", "-n", "git", "-f"]).arg(&allowed).arg("-I").arg(email).arg("-s").arg(&sig);
        match self.run(cmd, Some(&payload), "ssh-keygen") {
            Some((true, _, _)) => SigStatus::Good { signer: email.to_string() },
            Some((false, _, _)) => SigStatus::NoKey,
            None => SigStatus::Intact,
        }
    }

    /// Run `cmd` in an empty directory with a minimal environment. Returns
    /// (success, stdout, stderr), or `None` if it could not run.
    fn run(&mut self, mut cmd: Command, stdin: Option<&Path>, tool: &str) -> Option<(bool, String, String)> {
        let keep: Vec<_> = ["PATH", "HOME", "GNUPGHOME", "LANG", "LC_ALL"]
            .iter()
            .filter_map(|k| std::env::var_os(k).map(|v| (*k, v)))
            .collect();
        let explicit_gnupg = cmd.get_envs().any(|(k, _)| k == "GNUPGHOME");
        cmd.env_clear();
        for (k, v) in keep {
            if !(explicit_gnupg && k == "GNUPGHOME") {
                cmd.env(k, v);
            }
        }
        if explicit_gnupg {
            cmd.env("GNUPGHOME", self.tmp.path().join("gnupg"));
        }
        let stdin = match stdin {
            Some(p) => Stdio::from(std::fs::File::open(p).ok()?),
            None => Stdio::null(),
        };
        cmd.current_dir(self.tmp.path()).stdin(stdin).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let why = if e.kind() == std::io::ErrorKind::NotFound { "is not installed" } else { "could not run" };
                self.notes.insert(format!("`{tool}` {why}; some commit signatures were not verified"));
                return None;
            }
        };
        let start = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(st)) => break st,
                Ok(None) if start.elapsed() > TIMEOUT => {
                    let _ = child.kill();
                    let _ = child.wait();
                    self.notes.insert(format!("`{tool}` timed out; some commit signatures were not verified"));
                    return None;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                Err(_) => return None,
            }
        };
        let mut out = String::new();
        let mut err = String::new();
        if let Some(mut o) = child.stdout.take() {
            let _ = o.read_to_string(&mut out);
        }
        if let Some(mut e) = child.stderr.take() {
            let _ = e.read_to_string(&mut err);
        }
        Some((status.success(), out, err))
    }
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").trim().to_string()
}

/// Interpret GnuPG `--status-fd` output.
pub fn gpg_status(out: &str) -> SigStatus {
    let mut sig_time = None;
    let mut key_expired = None;
    let mut verdict = None;
    for line in out.lines() {
        let Some(rest) = line.strip_prefix("[GNUPG:] ") else { continue };
        let mut it = rest.split_whitespace();
        let tag = it.next().unwrap_or("");
        match tag {
            "VALIDSIG" => sig_time = it.nth(2).and_then(|t| t.parse::<i64>().ok()),
            "KEYEXPIRED" => key_expired = it.next().and_then(|t| t.parse::<i64>().ok()),
            "GOODSIG" | "EXPKEYSIG" | "EXPSIG" | "REVKEYSIG" | "BADSIG" | "ERRSIG" | "NO_PUBKEY" => {
                let uid = it.skip(1).collect::<Vec<_>>().join(" ");
                // BADSIG wins over anything else in the stream.
                if verdict.as_ref().is_none_or(|(t, _)| *t != "BADSIG") {
                    verdict = Some((tag, uid));
                }
            }
            _ => {}
        }
    }
    match verdict {
        Some(("GOODSIG", uid)) => SigStatus::Good { signer: uid },
        Some(("BADSIG", uid)) => SigStatus::Bad(format!("bad signature claiming to be from {uid}")),
        // A signature made while the key was still valid stays good after it expires.
        Some(("EXPKEYSIG", uid)) => match (sig_time, key_expired) {
            (Some(s), Some(k)) if s < k => SigStatus::Good { signer: uid },
            _ => SigStatus::Expired,
        },
        Some(("EXPSIG", _)) => SigStatus::Expired,
        Some(("REVKEYSIG", _)) => SigStatus::Revoked,
        Some(("ERRSIG" | "NO_PUBKEY", _)) => SigStatus::NoKey,
        _ => SigStatus::Unchecked("gpg gave no verdict".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpg_status_lines() {
        let good = "[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG B5690EEEBB952194 GitHub <noreply@github.com>\n[GNUPG:] VALIDSIG X 2026-11-18 1795022444 0";
        assert_eq!(gpg_status(good), SigStatus::Good { signer: "GitHub <noreply@github.com>".into() });
        let bad = "[GNUPG:] BADSIG B5690EEEBB952194 GitHub <noreply@github.com>";
        assert!(matches!(gpg_status(bad), SigStatus::Bad(_)));
        // Real output for a 2022 merge signed by the key that expired in 2024.
        let exp = "[GNUPG:] KEYEXPIRED 1705435200\n[GNUPG:] EXPKEYSIG 4AEE18F83AFDEB23 GitHub (web-flow commit signing) <noreply@github.com>\n[GNUPG:] VALIDSIG 5DE3 2022-11-02 1667426639 0 4";
        assert!(matches!(gpg_status(exp), SigStatus::Good { .. }));
        let late = "[GNUPG:] KEYEXPIRED 1705435200\n[GNUPG:] EXPKEYSIG 4AEE GitHub\n[GNUPG:] VALIDSIG 5DE3 2025-01-01 1735689600 0";
        assert_eq!(gpg_status(late), SigStatus::Expired);
        assert_eq!(gpg_status("[GNUPG:] ERRSIG 1234 1 8 00 0 9"), SigStatus::NoKey);
        assert!(matches!(gpg_status(""), SigStatus::Unchecked(_)));
    }

    #[test]
    fn formats() {
        assert_eq!(format_of(b"-----BEGIN PGP SIGNATURE-----\n"), SigFormat::Gpg);
        assert_eq!(format_of(b"-----BEGIN SSH SIGNATURE-----\n"), SigFormat::Ssh);
        assert_eq!(format_of(b"-----BEGIN SIGNED MESSAGE-----\n"), SigFormat::X509);
        assert_eq!(format_of(b"garbage"), SigFormat::Unknown);
    }

    #[test]
    fn split_unwraps_continuation_lines() {
        let raw = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\ngpgsig -----BEGIN SSH SIGNATURE-----\n abc\n \n -----END SSH SIGNATURE-----\n\nmsg\n";
        let s = split_signature(raw, gix::hash::Kind::Sha1).unwrap();
        assert_eq!(s.format, SigFormat::Ssh);
        assert_eq!(s.signature, b"-----BEGIN SSH SIGNATURE-----\nabc\n\n-----END SSH SIGNATURE-----\n");
        assert_eq!(
            s.payload,
            b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\n\nmsg\n"
        );
    }

    #[test]
    fn bundled_web_flow_keyring_verifies_and_rejects() {
        // A tampered payload under a real-looking signature must never be Good.
        let mut v = Verifier::new(None).unwrap();
        let s = SignedCommit {
            signature: b"-----BEGIN PGP SIGNATURE-----\n\nwsBcBAABCAAQBQJ\n-----END PGP SIGNATURE-----\n".to_vec(),
            payload: b"tree x\n\nmsg\n".to_vec(),
            format: SigFormat::Gpg,
        };
        let c = v.verify(&s, "noreply@github.com");
        assert!(c.web_flow);
        assert!(!matches!(c.status, SigStatus::Good { .. }), "{c:?}");
    }

    fn sh(dir: &Path, prog: &str, args: &[&str]) -> String {
        let out = Command::new(prog)
            .args(args)
            .current_dir(dir)
            .env("HOME", dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(out.status.success(), "{prog} {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    #[test]
    fn ssh_signed_commit_good_intact_and_tampered() {
        if Command::new("ssh-keygen").arg("-?").output().is_err() {
            eprintln!("ssh-keygen not installed; skipped");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        sh(d, "ssh-keygen", &["-q", "-t", "ed25519", "-N", "", "-f", "key", "-C", "t"]);
        sh(d, "git", &["init", "-q", "repo"]);
        let r = d.join("repo");
        let id = ["-c", "user.name=Signer", "-c", "user.email=s@example.com"];
        let key = format!("user.signingkey={}", d.join("key").display());
        let mut args = id.to_vec();
        args.extend(["-c", "gpg.format=ssh", "-c", &key, "commit", "-q", "-S", "--allow-empty", "-m", "signed"]);
        sh(&r, "git", &args);
        let head = sh(&r, "git", &["rev-parse", "HEAD"]);
        // Same commit with one byte of the message changed, signature kept.
        let raw = sh(&r, "git", &["cat-file", "commit", "HEAD"]).replace("signed", "signeD");
        std::fs::write(d.join("raw"), format!("{raw}\n")).unwrap();
        let forged = sh(&r, "git", &["hash-object", "-t", "commit", "-w", "../raw"]);

        let repo = GitRepo::discover(&r).unwrap();
        let sig = |h: &str| repo.commit_signature(ObjectId::from_hex(h.as_bytes()).unwrap()).unwrap().unwrap();
        let mut v = Verifier::new(None).unwrap();
        assert_eq!(v.verify(&sig(&head), "s@example.com").status, SigStatus::Intact);
        assert!(matches!(v.verify(&sig(&forged), "s@example.com").status, SigStatus::Bad(_)));

        let pubkey = std::fs::read_to_string(d.join("key.pub")).unwrap();
        std::fs::write(d.join("allowed"), format!("s@example.com {pubkey}")).unwrap();
        let mut v = Verifier::new(Some(d.join("allowed"))).unwrap();
        assert!(matches!(v.verify(&sig(&head), "s@example.com").status, SigStatus::Good { .. }));
        assert_eq!(v.verify(&sig(&head), "other@example.com").status, SigStatus::NoKey);
        // Claiming GitHub as committer with an SSH signature is never good.
        assert!(matches!(v.verify(&sig(&head), GITHUB_EMAIL).status, SigStatus::Bad(_)));
    }
}

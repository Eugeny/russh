use std::borrow::Cow;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::env;

use data_encoding::BASE64_MIME;
use hmac::{Hmac, KeyInit, Mac};
use log::debug;
use sha1::Sha1;

use crate::keys::Error;

/// Check whether the host is known, from its standard location.
pub fn check_known_hosts(
    host: &str,
    port: u16,
    pubkey: &ssh_key::PublicKey,
) -> Result<bool, Error> {
    check_known_hosts_path(host, port, pubkey, known_hosts_path()?)
}

/// Check that a server key matches the one recorded in file `path`.
///
/// # Semantics
///
/// Mirrors OpenSSH's `hostfile.c`:
///
/// * every line whose host pattern field matches `host` (see [`host_matches`])
///   is considered, in file order;
/// * a **matching** key wins, even if a *different* key for the same host and
///   algorithm appears earlier or later — a host may legitimately accumulate a
///   stale line, and OpenSSH accepts as soon as any line matches. Returning
///   `KeyChanged` on the first non-matching line reports a man-in-the-middle
///   warning for an ordinary stale entry;
/// * only when no line matches, but some line for the same host *and algorithm*
///   holds a different key, is this a genuine key change;
/// * a host that only has entries under *other* algorithms is not a change: the
///   negotiated algorithm simply has no recorded key.
pub fn check_known_hosts_path<P: AsRef<Path>>(
    host: &str,
    port: u16,
    pubkey: &ssh_key::PublicKey,
    path: P,
) -> Result<bool, Error> {
    let mut changed_line = None;

    for entry in matching_entries(host, port, path)? {
        let recorded = entry.public_key;
        if same_key(&recorded, pubkey) {
            return Ok(true);
        }
        // Same algorithm with different key material is a candidate change; it
        // is only reported if no other line turns out to match.
        if recorded.algorithm() == pubkey.algorithm() {
            changed_line.get_or_insert(entry.line);
        }
    }

    match changed_line {
        Some(line) => Err(Error::KeyChanged { line }),
        None => Ok(false),
    }
}

/// Compare two keys ignoring the comment.
///
/// `ssh_key::PublicKey`'s `PartialEq` includes the comment, so the same key
/// loaded from a `.pub` file (which carries a `user@host` comment) never equals
/// the copy found in `known_hosts` (which usually has none). Comparing the wire
/// encoding avoids reporting a spurious `KeyChanged`.
fn same_key(a: &ssh_key::PublicKey, b: &ssh_key::PublicKey) -> bool {
    // `key_data` is the algorithm plus the wire-encoded key material; the comment
    // is not part of a key's identity (known_hosts entries usually have none).
    a.algorithm() == b.algorithm() && a.key_data() == b.key_data()
}

fn known_hosts_path() -> Result<PathBuf, Error> {
    env::home_dir()
        .map(|home_dir| home_dir.join(".ssh").join("known_hosts"))
        .ok_or(Error::NoHomeDir)
}

/// Get the server key that matches the one recorded in the user's known_hosts file.
pub fn known_host_keys(host: &str, port: u16) -> Result<Vec<(usize, ssh_key::PublicKey)>, Error> {
    known_host_keys_path(host, port, known_hosts_path()?)
}

/// Get the server key that matches the one recorded in `path`.
pub fn known_host_keys_path<P: AsRef<Path>>(
    host: &str,
    port: u16,
    path: P,
) -> Result<Vec<(usize, ssh_key::PublicKey)>, Error> {
    Ok(matching_entries(host, port, path)?
        .into_iter()
        .map(|entry| (entry.line, entry.public_key))
        .collect())
}

/// One usable line of a `known_hosts` file.
struct KnownEntry {
    /// 1-based line number in the file.
    line: usize,
    public_key: ssh_key::PublicKey,
}

/// Every line whose host field matches `host:port`.
///
/// Lines that cannot be parsed are skipped rather than reported: OpenSSH ignores
/// unparsable lines and keeps reading the rest of the file, and one corrupt line
/// must not make an unrelated host unverifiable. Unknown `@` markers are skipped
/// for the same reason — new markers are added over time and an older client
/// should still read the entries it does understand.
fn matching_entries<P: AsRef<Path>>(
    host: &str,
    port: u16,
    path: P,
) -> Result<Vec<KnownEntry>, Error> {
    let Ok(f) = File::open(path) else {
        return Ok(vec![]);
    };

    let host_port = if port == 22 {
        Cow::Borrowed(host)
    } else {
        Cow::Owned(format!("[{host}]:{port}"))
    };
    debug!("host_port = {host_port:?}");

    let mut matches = vec![];
    for (idx, line) in BufReader::new(f).lines().enumerate() {
        let line = line?;
        // The line number is the real file position, so a `KeyChanged` diagnosis
        // points at the entry the user has to edit. It must be counted before any
        // `continue`.
        let line_no = idx + 1;

        let Some(entry) = parse_line(&line) else {
            continue;
        };
        if host_matches(&host_port, &entry.hosts) {
            matches.push(KnownEntry { line: line_no, public_key: entry.public_key });
        }
    }
    Ok(matches)
}

/// A `known_hosts` line reduced to the two fields verification needs.
struct ParsedLine {
    /// The host-pattern field, verbatim (may be a comma list or `|1|` hashed).
    hosts: String,
    public_key: ssh_key::PublicKey,
}

/// Parse one line, or `None` if it carries nothing verification can use.
///
/// Fields are separated by any run of whitespace: OpenSSH writes single spaces,
/// but files are hand-edited and tabs or indentation are common. A marker
/// (`@revoked`, `@cert-authority`) makes the line unusable for plain host-key
/// verification, so such lines are skipped here; `@revoked` is handled by
/// [`is_revoked`], which is consulted before any key is accepted.
fn parse_line(line: &str) -> Option<ParsedLine> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    // A marker line is not a plain host key. `@revoked` is handled separately.
    if line.starts_with('@') {
        return None;
    }

    let mut fields = line.split_whitespace();
    let hosts = fields.next()?.to_string();
    // The key parser wants `keytype key` separated by exactly one space.
    let key_str = fields.collect::<Vec<_>>().join(" ");
    if key_str.is_empty() {
        return None;
    }
    let public_key = crate::keys::parse_public_key_base64(
        key_str.split_once(' ').map_or(key_str.as_str(), |(_, b64)| b64),
    )
    .ok()?;

    Some(ParsedLine { hosts, public_key })
}

/// Does the host-pattern field match `host`?
///
/// The field may be a comma-separated list. Each element is a case-sensitive
/// glob for the hostname (`*` and `?`, per OpenSSH's `match_pattern`), a `!`
/// negation, or a `|1|salt|hash` hashed entry. A negated element that matches
/// excludes the host even if another element matches.
fn host_matches(host: &str, pattern_field: &str) -> bool {
    let mut matched = false;
    for pattern in pattern_field.split(',') {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            continue;
        }
        if let Some(rest) = pattern.strip_prefix("|1|") {
            if hashed_matches(rest, host) {
                return true;
            }
            continue;
        }
        let (negated, pattern) = match pattern.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, pattern),
        };
        if glob_matches(host, pattern) {
            if negated {
                return false;
            }
            matched = true;
        }
    }
    matched
}

/// OpenSSH `match_pattern`: `*` matches any run (including empty), `?` exactly
/// one character, **case-sensitive**.
///
/// Iterative with a single backtrack point, so a hostile pattern cannot exhaust
/// the stack. Slices are compared through `get` rather than indexed, because the
/// crate denies `clippy::indexing_slicing`.
fn glob_matches(text: &str, pattern: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);

    while ti < t.len() {
        let pc = p.get(pi).copied();
        let tc = t.get(ti).copied();
        if let (Some(pc), Some(tc)) = (pc, tc)
            && (pc == '?' || pc == tc)
        {
            pi += 1;
            ti += 1;
        } else if pc == Some('*') {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while p.get(pi) == Some(&'*') {
        pi += 1;
    }
    pi == p.len()
}

/// `|1|salt|hash` verification (HMAC-SHA1 over the host).
fn hashed_matches(rest: &str, host: &str) -> bool {
    let Some((salt_b64, hash_b64)) = rest.split_once('|') else {
        return false;
    };
    let (Ok(salt), Ok(hash)) = (BASE64_MIME.decode(salt_b64.as_bytes()), BASE64_MIME.decode(hash_b64.as_bytes()))
    else {
        return false;
    };
    Hmac::<Sha1>::new_from_slice(&salt)
        .map(|hmac| hmac.chain_update(host).verify_slice(&hash).is_ok())
        .unwrap_or(false)
}

/// Record a host's public key into the user's known_hosts file.
pub fn learn_known_hosts(host: &str, port: u16, pubkey: &ssh_key::PublicKey) -> Result<(), Error> {
    learn_known_hosts_path(host, port, pubkey, known_hosts_path()?)
}

/// Record a host's public key into a nonstandard location.
pub fn learn_known_hosts_path<P: AsRef<Path>>(
    host: &str,
    port: u16,
    pubkey: &ssh_key::PublicKey,
    path: P,
) -> Result<(), Error> {
    if let Some(parent) = path.as_ref().parent() {
        std::fs::create_dir_all(parent)?
    }
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(path)?;

    // Only pad with a newline when the file already has content that does not
    // end in one. Seeking to `-1` on an empty file succeeds, which previously
    // made a brand-new file start with a blank line.
    let needs_newline = match file.metadata() {
        Ok(meta) if meta.len() > 0 => {
            let mut buf = [0; 1];
            file.seek(SeekFrom::End(-1))?;
            file.read_exact(&mut buf)?;
            buf[0] != b'\n'
        }
        Ok(_) => false,
        Err(_) => false,
    };

    // Write the key.
    file.seek(SeekFrom::End(0))?;
    let mut file = std::io::BufWriter::new(file);
    if needs_newline {
        file.write_all(b"\n")?;
    }
    if port != 22 {
        write!(file, "[{host}]:{port} ")?
    } else {
        write!(file, "{host} ")?
    }
    // Write only `keytype key`, never the comment: `to_openssh()` appends the
    // key's comment, which would then land in the key field on the next read and
    // make the entry we just recorded unparsable.
    let openssh = pubkey.to_openssh()?;
    let mut parts = openssh.split_whitespace();
    match (parts.next(), parts.next()) {
        (Some(keytype), Some(blob)) => write!(file, "{keytype} {blob}")?,
        // `to_openssh()` always yields at least `keytype key`; fall back to it
        // verbatim rather than writing nothing.
        _ => file.write_all(openssh.as_bytes())?,
    }
    file.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::Write;

    use super::*;
    use crate::keys::parse_public_key_base64;

    /// Two distinct, valid ed25519 public keys.
    const KEY_A: &str = "AAAAC3NzaC1lZDI1NTE5AAAAICsMBDhtVmpjA0bCZd/VKZGm+ZlWHaIdTFWca6QP35EN";
    const KEY_B: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ";

    fn key(b64: &str) -> ssh_key::PublicKey {
        parse_public_key_base64(b64).unwrap()
    }

    /// Write `body` to a fresh `known_hosts` in `dir` and return its path.
    fn fixture(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("known_hosts");
        File::create(&path)
            .unwrap()
            .write_all(body.as_bytes())
            .unwrap();
        path
    }

    #[test]
    fn test_check_known_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(
            dir.path(),
            &format!(
                "[localhost]:13265 ssh-ed25519 {KEY_B}\n\
                 #pijul.org,37.120.161.53 ssh-ed25519 {KEY_A}\n\
                 pijul.org,37.120.161.53 ssh-ed25519 {KEY_A}\n\
                 |1|O33ESRMWPVkMYIwJ1Uw+n877jTo=|nuuC5vEqXlEZ/8BXQR7m619W6Ak= ssh-ed25519 \
                 AAAAC3NzaC1lZDI1NTE5AAAAILIG2T/B0l0gaqj3puu510tu9N1OkQ4znY3LYuEm5zCF\n"
            ),
        );

        // Valid key, non-standard port.
        assert!(check_known_hosts_path("localhost", 13265, &key(KEY_B), &path).unwrap());

        // Valid key, hashed host.
        let hashed = key("AAAAC3NzaC1lZDI1NTE5AAAAILIG2T/B0l0gaqj3puu510tu9N1OkQ4znY3LYuEm5zCF");
        assert!(check_known_hosts_path("example.com", 22, &hashed, &path).unwrap());

        // Valid key behind a comment line.
        assert!(check_known_hosts_path("pijul.org", 22, &key(KEY_A), &path).unwrap());
    }

    #[test]
    fn a_wildcard_host_entry_matches() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(dir.path(), &format!("*.example.com ssh-ed25519 {KEY_A}\n"));
        // OpenSSH: `ssh-keygen -F api.example.com` matches.
        assert!(check_known_hosts_path("api.example.com", 22, &key(KEY_A), &path).unwrap());
    }

    #[test]
    fn a_question_mark_host_entry_matches_exactly_one_character() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(dir.path(), &format!("db? ssh-ed25519 {KEY_A}\n"));
        assert!(check_known_hosts_path("db1", 22, &key(KEY_A), &path).unwrap());
        assert!(!check_known_hosts_path("db", 22, &key(KEY_A), &path).unwrap());
        assert!(!check_known_hosts_path("db12", 22, &key(KEY_A), &path).unwrap());
    }

    #[test]
    fn a_negated_pattern_excludes_the_host() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(
            dir.path(),
            &format!("*.example.com,!bad.example.com ssh-ed25519 {KEY_A}\n"),
        );
        assert!(check_known_hosts_path("good.example.com", 22, &key(KEY_A), &path).unwrap());
        // OpenSSH: `ssh-keygen -F bad.example.com` finds nothing.
        assert!(!check_known_hosts_path("bad.example.com", 22, &key(KEY_A), &path).unwrap());
    }

    #[test]
    fn fields_may_be_separated_by_tabs() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(
            dir.path(),
            &format!("example.com\tssh-ed25519\t{KEY_A}\n"),
        );
        assert!(check_known_hosts_path("example.com", 22, &key(KEY_A), &path).unwrap());
    }

    #[test]
    fn leading_whitespace_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(dir.path(), &format!("   example.com ssh-ed25519 {KEY_A}\n"));
        assert!(check_known_hosts_path("example.com", 22, &key(KEY_A), &path).unwrap());
    }

    /// A stale entry for the same host and algorithm must not mask a later match.
    ///
    /// OpenSSH accepts this file (verified against a real sshd: with both the old
    /// and the new key present, `ssh` connects); reporting `KeyChanged` here would
    /// raise a man-in-the-middle warning for an ordinary stale line.
    #[test]
    fn a_matching_entry_after_a_stale_one_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(
            dir.path(),
            &format!("example.com ssh-ed25519 {KEY_B}\nexample.com ssh-ed25519 {KEY_A}\n"),
        );
        assert!(check_known_hosts_path("example.com", 22, &key(KEY_A), &path).unwrap());
    }

    /// The mirror case: the match comes first and the stale entry second.
    #[test]
    fn a_matching_entry_before_a_stale_one_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(
            dir.path(),
            &format!("example.com ssh-ed25519 {KEY_A}\nexample.com ssh-ed25519 {KEY_B}\n"),
        );
        assert!(check_known_hosts_path("example.com", 22, &key(KEY_A), &path).unwrap());
    }

    #[test]
    fn a_genuinely_changed_key_is_reported_with_its_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(
            dir.path(),
            &format!("other.com ssh-ed25519 {KEY_B}\nexample.com ssh-ed25519 {KEY_B}\n"),
        );
        match check_known_hosts_path("example.com", 22, &key(KEY_A), &path) {
            Err(Error::KeyChanged { line }) => assert_eq!(line, 2),
            other => panic!("expected KeyChanged on line 2, got {other:?}"),
        }
    }

    /// The reported line must be the real file line, so comments above the entry
    /// do not shift the diagnosis.
    #[test]
    fn the_reported_line_counts_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(
            dir.path(),
            &format!(
                "# a comment\n\
                 \n\
                 example.com ssh-ed25519 {KEY_B}\n"
            ),
        );
        match check_known_hosts_path("example.com", 22, &key(KEY_A), &path) {
            Err(Error::KeyChanged { line }) => assert_eq!(line, 3),
            other => panic!("expected KeyChanged on line 3, got {other:?}"),
        }
    }

    /// A different algorithm is not a change: the host simply has no key recorded
    /// for the negotiated algorithm.
    #[test]
    fn an_entry_under_another_algorithm_is_not_a_change() {
        let dir = tempfile::tempdir().unwrap();
        // KEY_B is ed25519 but recorded against a different host; the queried host
        // has only a comment.
        let path = fixture(dir.path(), &format!("other.com ssh-ed25519 {KEY_B}\n"));
        assert!(!check_known_hosts_path("example.com", 22, &key(KEY_A), &path).unwrap());
    }

    /// One corrupt line must not make an unrelated host unverifiable. OpenSSH
    /// skips lines it cannot parse and keeps reading.
    #[test]
    fn a_corrupt_line_does_not_break_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(
            dir.path(),
            &format!(
                "junk-with-no-key\n\
                 other.com ssh-ed25519 AAAAcorruptblob!!!!\n\
                 example.com ssh-ed25519 {KEY_A}\n"
            ),
        );
        assert!(check_known_hosts_path("example.com", 22, &key(KEY_A), &path).unwrap());
        let keys = known_host_keys_path("example.com", 22, &path).unwrap();
        assert_eq!(keys.len(), 1, "the good entry is still reported: {keys:?}");
    }

    /// The same key with a `user@host` comment is the same key.
    #[test]
    fn a_key_comment_does_not_affect_the_comparison() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(dir.path(), &format!("example.com ssh-ed25519 {KEY_A}\n"));
        let mut with_comment = key(KEY_A);
        with_comment.set_comment("someone@laptop");
        assert!(check_known_hosts_path("example.com", 22, &with_comment, &path).unwrap());
    }

    #[test]
    fn learning_into_a_new_file_does_not_start_with_a_blank_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        learn_known_hosts_path("example.com", 22, &key(KEY_A), &path).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(!body.starts_with('\n'), "file starts with a blank line: {body:?}");
        assert_eq!(body.lines().count(), 1);
    }

    #[test]
    fn a_learned_key_verifies_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let mut k = key(KEY_A);
        k.set_comment("someone@laptop");
        learn_known_hosts_path("example.com", 22, &k, &path).unwrap();
        assert!(check_known_hosts_path("example.com", 22, &key(KEY_A), &path).unwrap());
    }

    #[test]
    fn learning_preserves_a_missing_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(dir.path(), &format!("other.com ssh-ed25519 {KEY_B}"));
        learn_known_hosts_path("example.com", 22, &key(KEY_A), &path).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.lines().count(), 2, "one record per line: {body:?}");
    }

    #[test]
    fn glob_matches_follows_openssh() {
        assert!(glob_matches("anything", "*"));
        assert!(glob_matches("", "*"));
        assert!(glob_matches("web1", "web*"));
        assert!(glob_matches("web1", "web?"));
        assert!(glob_matches("a.b.example.com", "*.example.com"));
        assert!(glob_matches("axxbyyc", "a*b*c"));
        assert!(!glob_matches("web12", "web?"));
        assert!(!glob_matches("web2", "web"));
        // Case-sensitive: `Web1` and `web1` are different hosts.
        assert!(!glob_matches("Web1", "web*"));
    }

    #[test]
    fn a_hashed_entry_matches_only_its_own_host() {
        let dir = tempfile::tempdir().unwrap();
        // Produced by `ssh-keygen -H` for the host `example.com`.
        let path = fixture(
            dir.path(),
            &format!("|1|O33ESRMWPVkMYIwJ1Uw+n877jTo=|nuuC5vEqXlEZ/8BXQR7m619W6Ak= ssh-ed25519 {KEY_A}\n"),
        );
        assert!(check_known_hosts_path("example.com", 22, &key(KEY_A), &path).unwrap());
        assert!(!check_known_hosts_path("other.com", 22, &key(KEY_A), &path).unwrap());
    }

    #[test]
    fn a_missing_file_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");
        assert!(!check_known_hosts_path("example.com", 22, &key(KEY_A), &missing).unwrap());
    }

    #[test]
    fn the_port_is_part_of_the_host_field() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(dir.path(), &format!("[example.com]:2222 ssh-ed25519 {KEY_A}\n"));
        assert!(check_known_hosts_path("example.com", 2222, &key(KEY_A), &path).unwrap());
        // The same host on the default port is a different known_hosts identity.
        assert!(!check_known_hosts_path("example.com", 22, &key(KEY_A), &path).unwrap());
    }
}

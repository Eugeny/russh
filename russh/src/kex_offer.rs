use ssh_encoding::Decode;

use crate::Error;
use crate::helpers::NameList;
use crate::parsing::ensure_end;

/// Whether the peer is a client or a server.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub enum PeerRole {
    /// The remote peer is an SSH client.
    Client,
    /// The remote peer is an SSH server.
    Server,
}

/// Algorithm and option lists offered by the peer in an `SSH_MSG_KEXINIT`
/// packet (RFC 4253 §7.1).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KexOffer {
    /// Whether the offering peer is a client or server.
    pub peer_role: PeerRole,
    /// Offered key exchange algorithms.
    pub kex: Vec<String>,
    /// Offered server host key algorithms.
    pub key: Vec<String>,
    /// Offered client-to-server encryption algorithms.
    pub client_cipher: Vec<String>,
    /// Offered server-to-client encryption algorithms.
    pub server_cipher: Vec<String>,
    /// Offered client-to-server MAC algorithms.
    pub client_mac: Vec<String>,
    /// Offered server-to-client MAC algorithms.
    pub server_mac: Vec<String>,
    /// Offered client-to-server compression algorithms.
    pub client_compression: Vec<String>,
    /// Offered server-to-client compression algorithms.
    pub server_compression: Vec<String>,
    /// Offered client-to-server languages.
    pub client_languages: Vec<String>,
    /// Offered server-to-client languages.
    pub server_languages: Vec<String>,
    /// Whether a guessed key exchange packet follows immediately.
    pub first_kex_packet_follows: bool,
}

impl KexOffer {
    /// Decode a peer's `SSH_MSG_KEXINIT` packet payload (starting with
    /// `msg::KEXINIT` and its 16-byte cookie) into a [`KexOffer`].
    pub(crate) fn decode_kexinit(peer_role: PeerRole, buffer: &[u8]) -> Result<Self, Error> {
        let &Some(mut r) = &buffer.get(17..) else {
            return Err(Error::Inconsistent);
        };

        let kex = NameList::decode(&mut r)?.0;
        let key = NameList::decode(&mut r)?.0;
        let client_cipher = NameList::decode(&mut r)?.0;
        let server_cipher = NameList::decode(&mut r)?.0;
        let client_mac = NameList::decode(&mut r)?.0;
        let server_mac = NameList::decode(&mut r)?.0;
        let client_compression = NameList::decode(&mut r)?.0;
        let server_compression = NameList::decode(&mut r)?.0;
        let client_languages = NameList::decode(&mut r)?.0;
        let server_languages = NameList::decode(&mut r)?.0;
        let first_kex_packet_follows = u8::decode(&mut r)? != 0;
        u32::decode(&mut r)?; // reserved
        ensure_end(&r)?;

        Ok(Self {
            peer_role,
            kex,
            key,
            client_cipher,
            server_cipher,
            client_mac,
            server_mac,
            client_compression,
            server_compression,
            client_languages,
            server_languages,
            first_kex_packet_follows,
        })
    }

    fn visit_hassh_chunks(&self, mut f: impl FnMut(&str)) {
        let (enc, mac, cmp) = match self.peer_role {
            PeerRole::Client => (
                &self.client_cipher,
                &self.client_mac,
                &self.client_compression,
            ),
            PeerRole::Server => (
                &self.server_cipher,
                &self.server_mac,
                &self.server_compression,
            ),
        };

        for (i, list) in [&self.kex, enc, mac, cmp].iter().enumerate() {
            if i > 0 {
                f(";");
            }
            for (j, s) in list.iter().enumerate() {
                if j > 0 {
                    f(",");
                }
                f(s);
            }
        }
    }

    /// Returns the unhashed HASSH algorithm string (`hasshAlgorithms` for a
    /// [`PeerRole::Client`] offer or `hasshServerAlgorithms` for a
    /// [`PeerRole::Server`] offer).
    ///
    /// Formatted as `kex;encryption;mac;compression`, where each field is a
    /// comma-separated list of the peer's offered algorithms in its transmit
    /// direction (client-to-server for clients, server-to-client for servers).
    pub fn hassh_algorithms(&self) -> String {
        let mut hassh_str = String::with_capacity(1024);
        self.visit_hassh_chunks(|s| hassh_str.push_str(s));
        hassh_str
    }

    /// Returns the lowercase hex MD5 HASSH fingerprint (`hassh` for a
    /// [`PeerRole::Client`] offer or `hasshServer` for a [`PeerRole::Server`]
    /// offer) computed over [`Self::hassh_algorithms`].
    pub fn hassh(&self) -> String {
        let mut ctx = md5::Context::new();
        self.visit_hassh_chunks(|s| ctx.consume(s.as_bytes()));
        format!("{:x}", ctx.finalize())
    }
}

#[cfg(test)]
mod tests {
    use ssh_encoding::Encode;

    use super::*;
    use crate::msg;

    #[test]
    fn kex_offer_decodes_all_fields() {
        let mut buf = vec![msg::KEXINIT];
        buf.extend_from_slice(&[0u8; 16]);
        let encode_list = |buf: &mut Vec<u8>, items: &[&str]| {
            NameList(items.iter().map(|s| s.to_string()).collect())
                .encode(buf)
                .unwrap();
        };
        encode_list(&mut buf, &["mlkem768x25519-sha256", "curve25519-sha256"]);
        encode_list(&mut buf, &["ssh-ed25519"]);
        encode_list(&mut buf, &["chacha20-poly1305@openssh.com"]);
        encode_list(&mut buf, &["aes256-gcm@openssh.com"]);
        encode_list(&mut buf, &["hmac-sha2-256-etm@openssh.com"]);
        encode_list(&mut buf, &["hmac-sha2-512-etm@openssh.com"]);
        encode_list(&mut buf, &["none"]);
        encode_list(&mut buf, &["zlib@openssh.com", "none"]);
        encode_list(&mut buf, &["en-US", "fr"]);
        encode_list(&mut buf, &[]);
        1u8.encode(&mut buf).unwrap();
        0u32.encode(&mut buf).unwrap();

        let offer = KexOffer::decode_kexinit(PeerRole::Client, &buf).unwrap();
        assert_eq!(
            offer,
            KexOffer {
                peer_role: PeerRole::Client,
                kex: vec![
                    "mlkem768x25519-sha256".to_string(),
                    "curve25519-sha256".to_string(),
                ],
                key: vec!["ssh-ed25519".to_string()],
                client_cipher: vec!["chacha20-poly1305@openssh.com".to_string()],
                server_cipher: vec!["aes256-gcm@openssh.com".to_string()],
                client_mac: vec!["hmac-sha2-256-etm@openssh.com".to_string()],
                server_mac: vec!["hmac-sha2-512-etm@openssh.com".to_string()],
                client_compression: vec!["none".to_string()],
                server_compression: vec!["zlib@openssh.com".to_string(), "none".to_string()],
                client_languages: vec!["en-US".to_string(), "fr".to_string()],
                server_languages: vec![],
                first_kex_packet_follows: true,
            }
        );
    }

    #[test]
    fn hassh_client_and_server_vectors() {
        let mut buf = vec![msg::KEXINIT];
        buf.extend_from_slice(&[0u8; 16]);
        let encode_list = |buf: &mut Vec<u8>, items: &[&str]| {
            NameList(items.iter().map(|s| s.to_string()).collect())
                .encode(buf)
                .unwrap();
        };
        encode_list(&mut buf, &["mlkem768x25519-sha256", "curve25519-sha256"]);
        encode_list(&mut buf, &["ssh-ed25519"]);
        encode_list(&mut buf, &["chacha20-poly1305@openssh.com"]);
        encode_list(&mut buf, &["aes256-gcm@openssh.com"]);
        encode_list(&mut buf, &["hmac-sha2-256-etm@openssh.com"]);
        encode_list(&mut buf, &["hmac-sha2-512-etm@openssh.com"]);
        encode_list(&mut buf, &["none"]);
        encode_list(&mut buf, &["zlib@openssh.com", "none"]);
        encode_list(&mut buf, &[]);
        encode_list(&mut buf, &[]);
        0u8.encode(&mut buf).unwrap();
        0u32.encode(&mut buf).unwrap();

        let client_offer = KexOffer::decode_kexinit(PeerRole::Client, &buf).unwrap();
        assert_eq!(
            client_offer.hassh_algorithms(),
            "mlkem768x25519-sha256,curve25519-sha256;chacha20-poly1305@openssh.com;hmac-sha2-256-etm@openssh.com;none"
        );
        assert_eq!(client_offer.hassh(), "f41fea0a5a7506f01e192aa2e290305e");

        let server_offer = KexOffer::decode_kexinit(PeerRole::Server, &buf).unwrap();
        assert_eq!(
            server_offer.hassh_algorithms(),
            "mlkem768x25519-sha256,curve25519-sha256;aes256-gcm@openssh.com;hmac-sha2-512-etm@openssh.com;zlib@openssh.com,none"
        );
        assert_eq!(server_offer.hassh(), "66407c80b7f896b76cbdcefe6c9c6f04");

        // Empty algorithm list (e.g. AEAD-only peer sending empty MAC list).
        let empty_mac_offer = KexOffer {
            peer_role: PeerRole::Client,
            kex: vec!["curve25519-sha256".to_string()],
            key: vec![],
            client_cipher: vec!["chacha20-poly1305@openssh.com".to_string()],
            server_cipher: vec![],
            client_mac: vec![],
            server_mac: vec![],
            client_compression: vec!["none".to_string()],
            server_compression: vec![],
            client_languages: vec![],
            server_languages: vec![],
            first_kex_packet_follows: false,
        };
        assert_eq!(
            empty_mac_offer.hassh_algorithms(),
            "curve25519-sha256;chacha20-poly1305@openssh.com;;none"
        );
        assert_eq!(
            empty_mac_offer.hassh(),
            format!(
                "{:x}",
                md5::compute(empty_mac_offer.hassh_algorithms().as_bytes())
            )
        );
    }

    /// Real-world client (`hassh`) and server (`hasshServer`) test vectors
    /// extracted from `testing/Traces/ssh_zeek_test_pcaps.pcap` and verified
    /// against `testing/Baseline/tests.ssh_zeek_test_pcaps/ssh_cut.log` in
    /// <https://github.com/corelight/hassh> (v1.0.1, commit `8280c8d`,
    /// BSD-3-Clause).
    #[test]
    fn hassh_corelight_pcap_vectors() {
        let vectors: &[(PeerRole, &str, &str, &str, &str, &str, &str)] = &[
            // SSH-2.0-OpenSSH_3.8.1p1
            (PeerRole::Client, "c4fd9343cba76d12f0dd523fbe7c4da1", "diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1", "ssh-rsa,ssh-dss", "aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,arcfour,aes192-cbc,aes256-cbc,rijndael-cbc@lysator.liu.se,aes128-ctr,aes192-ctr,aes256-ctr", "hmac-md5,hmac-sha1,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96", "none,zlib"),
            // SSH-1.99-OpenSSH_3.9p1
            (PeerRole::Server, "f430cd6761697a6a658ee1d45ed22e49", "diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1", "ssh-rsa,ssh-dss", "aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,arcfour,aes192-cbc,aes256-cbc,rijndael-cbc@lysator.liu.se,aes128-ctr,aes192-ctr,aes256-ctr", "hmac-md5,hmac-sha1,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96", "none,zlib"),
            // SSH-1.99-Cisco-1.25
            (PeerRole::Client, "3cc67862bceac0f334c62ad1b76895b4", "diffie-hellman-group1-sha1", "ssh-rsa", "aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc", "hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96", "none"),
            // SSH-2.0-Cisco-1.25
            (PeerRole::Server, "3cc67862bceac0f334c62ad1b76895b4", "diffie-hellman-group1-sha1", "ssh-rsa", "aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc", "hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96", "none"),
            // SSH-2.0-OpenSSH_5.2
            (PeerRole::Client, "21b457a327ce7a2d4fce5ef2c42400bd", "diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1", "ssh-rsa,ssh-dss", "aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se", "hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96", "none,zlib@openssh.com,zlib"),
            // SSH-2.0-OpenSSH_5.8p1 Debian-1ubuntu3
            (PeerRole::Server, "60205d0b53ffd441ead5c43b5a6f1bc7", "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1", "ssh-rsa,ssh-dss,ecdsa-sha2-nistp256", "aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se", "hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96", "none,zlib@openssh.com"),
            // SSH-2.0-OpenSSH_5.9
            (PeerRole::Client, "fded76fff260754db84bd4725a931b7e", "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1", "ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-dss-cert-v01@openssh.com,ssh-rsa-cert-v00@openssh.com,ssh-dss-cert-v00@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-rsa,ssh-dss", "aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se", "hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-sha2-256,hmac-sha2-256-96,hmac-sha2-512,hmac-sha2-512-96,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96", "zlib@openssh.com,zlib,none"),
            // SSH-2.0-OpenSSH_6.6
            (PeerRole::Client, "e30029a55fea2fcd3501023fb659bfae", "curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1", "ssh-rsa-cert-v01@openssh.com,ssh-rsa-cert-v00@openssh.com,ssh-rsa,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,ssh-dss-cert-v01@openssh.com,ssh-dss-cert-v00@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,ssh-dss", "aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se", "hmac-md5-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-md5,hmac-sha1,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96", "none,zlib@openssh.com,zlib"),
            // SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.1
            (PeerRole::Server, "ce3c327f37ea2ec21f317fbc3fd1ea43", "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1", "ssh-rsa,ssh-dss,ecdsa-sha2-nistp256", "aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se", "hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-sha2-256,hmac-sha2-256-96,hmac-sha2-512,hmac-sha2-512-96,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96", "none,zlib@openssh.com"),
            // SSH-2.0-OpenSSH_6.2
            (PeerRole::Client, "1f120ecfc2c57fbdeaf66b93a3bf26ee", "diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1", "ssh-rsa-cert-v01@openssh.com,ssh-rsa-cert-v00@openssh.com,ssh-rsa,ssh-dss-cert-v01@openssh.com,ssh-dss-cert-v00@openssh.com,ssh-dss", "aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se", "hmac-md5-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-md5,hmac-sha1,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96", "none,zlib@openssh.com,zlib"),
            // SSH-1.99-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2
            (PeerRole::Server, "ba6d3d2aecbd0d91b01dfa7828110d70", "curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1", "ssh-rsa,ssh-dss,ecdsa-sha2-nistp256,ssh-ed25519", "aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se", "hmac-md5-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-md5,hmac-sha1,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96", "none,zlib@openssh.com"),
            // SSH-2.0-paramiko_1.15.2
            (PeerRole::Server, "d72f74b08466652d162ca02ad197b9ad", "diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1", "ssh-rsa", "aes128-ctr,aes256-ctr,aes128-cbc,blowfish-cbc,aes256-cbc,3des-cbc,arcfour128,arcfour256", "hmac-sha1,hmac-md5,hmac-sha1-96,hmac-md5-96", "none"),
            // SSH-2.0-OpenSSH_6.2
            (PeerRole::Client, "3b310af105a6d0567dc00a90451b0e6e", "diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1", "ssh-rsa-cert-v01@openssh.com,ssh-rsa-cert-v00@openssh.com,ssh-rsa,ssh-dss-cert-v01@openssh.com,ssh-dss-cert-v00@openssh.com,ssh-dss", "arcfour256", "hmac-md5-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-md5,hmac-sha1,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96", "none,zlib@openssh.com,zlib"),
            // SSH-1.99-OpenSSH_3.4+p1+gssapi+OpenSSH_3.7.1buf_fix+2006100301
            (PeerRole::Server, "5280acc8be4a17ac96c05b6f3bdaec60", "diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1", "ssh-rsa,ssh-dss", "aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,arcfour,aes192-cbc,aes256-cbc,rijndael-cbc@lysator.liu.se", "hmac-md5,hmac-sha1,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96", "none,zlib"),
            // SSH-2.0-OpenSSH_5.3
            (PeerRole::Server, "0f5053d1cc689128b6db47f340f3285f", "diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1", "ssh-rsa,ssh-dss", "aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se", "hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96", "none,zlib@openssh.com"),
            // SSH-2.0-OpenSSH_6.7
            (PeerRole::Client, "777e66d81dadd6002bf417dc5e1c61df", "curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256", "ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-dss-cert-v01@openssh.com,ssh-rsa-cert-v00@openssh.com,ssh-dss-cert-v00@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,ssh-rsa,ssh-dss", "aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,arcfour256,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se", "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-md5-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-md5,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96", "none,zlib@openssh.com,zlib"),
            // SSH-2.0-OpenSSH_6.7
            (PeerRole::Server, "41ed548e9e885f199ea6919370d83c68", "curve25519-sha256@libssh.org", "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com", "chacha20-poly1305@openssh.com", "hmac-sha2-512-etm@openssh.com", "none,zlib@openssh.com"),
            // SSH-2.0-OpenSSH_6.7
            (PeerRole::Client, "a708ee258c30a58517040d6611dce408", "curve25519-sha256@libssh.org", "ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-dss-cert-v01@openssh.com,ssh-rsa-cert-v00@openssh.com,ssh-dss-cert-v00@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,ssh-rsa,ssh-dss", "aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,arcfour256,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se", "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-md5-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-md5,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96", "none,zlib@openssh.com,zlib"),
            // SSH-2.0-OpenSSH_6.7
            (PeerRole::Client, "46c5bd9748882f1a5d75753fb7d47a61", "curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1", "ssh-rsa-cert-v01@openssh.com,ssh-rsa-cert-v00@openssh.com,ssh-rsa,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,ssh-dss-cert-v01@openssh.com,ssh-dss-cert-v00@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,ssh-dss", "aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,arcfour256,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se", "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-md5-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-md5,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96", "none,zlib@openssh.com,zlib"),
            // SSH-2.0-OpenSSH_5.3
            (PeerRole::Server, "b1c6c0d56317555b85c7005a3de29325", "diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1", "ssh-rsa,ssh-dss", "aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se", "hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96", "none,zlib@openssh.com"),
            // SSH-2.0-OpenSSH_6.7p1 Debian-3
            (PeerRole::Server, "3711ee816d3ea9975d96c39c31c54299", "curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1", "ssh-rsa,ssh-dss,ecdsa-sha2-nistp256,ssh-ed25519", "aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com", "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1", "none,zlib@openssh.com"),
            // SSH-2.0-OpenSSH_7.4
            (PeerRole::Client, "0df0d56bb50c6b2426d8d40234bf1826", "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c", "ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521", "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-cbc,aes192-cbc,aes256-cbc", "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1", "none,zlib@openssh.com,zlib"),
            // SSH-2.0-OpenSSH_7.5
            (PeerRole::Server, "a95c22bf8e9b19ed0a5dc74bb2f9c613", "curve25519-sha256", "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com", "chacha20-poly1305@openssh.com", "hmac-sha2-512-etm@openssh.com", "none,zlib@openssh.com"),
            // SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
            (PeerRole::Client, "06046964c022c6407d15a27b12a6a4fb", "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c", "ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa", "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com", "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1", "none,zlib@openssh.com,zlib"),
            // SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
            (PeerRole::Server, "b12d2871a1189eff20364cf5333619ee", "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1", "ssh-rsa,rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519", "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com", "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1", "none,zlib@openssh.com"),
            // SSH-2.0-PuTTY_Release_0.72
            (PeerRole::Client, "e77c2db7432e8cfbc42a96909a84fc8e", "curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,rsa2048-sha256,rsa1024-sha1,diffie-hellman-group1-sha1", "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-rsa,ssh-dss", "aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-ctr,aes192-cbc,aes128-ctr,aes128-cbc,chacha20-poly1305@openssh.com,3des-ctr,3des-cbc,blowfish-ctr,blowfish-cbc,arcfour256,arcfour128", "hmac-sha2-256,hmac-sha1,hmac-sha1-96,hmac-md5,hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha1-96-etm@openssh.com,hmac-md5-etm@openssh.com", "none,zlib,zlib@openssh.com"),
            // SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1
            (PeerRole::Client, "ae8bd7dd09970555aa4c6ed22adbbf56", "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-c", "ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,ssh-ed25519,sk-ssh-ed25519@openssh.com,rsa-sha2-512,rsa-sha2-256,ssh-rsa", "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com", "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1", "none,zlib@openssh.com,zlib"),
            // SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1
            (PeerRole::Server, "3ccd1778a76049721c71ad7d2bf62bbc", "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256", "rsa-sha2-512,rsa-sha2-256,ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519", "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com", "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1", "none,zlib@openssh.com"),
            // SSH-2.0-dropbear_2018.76
            (PeerRole::Client, "413e646031ea5204c5ec2fe2d5b7946e", "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,kexguess2@matt.ucc.asn.au", "ssh-rsa", "aes128-ctr,aes256-ctr,aes128-cbc,aes256-cbc,3des-ctr,3des-cbc", "hmac-sha1-96,hmac-sha1,hmac-sha2-256", "zlib@openssh.com,none"),
            // SSH-2.0-AsyncSSH_2.8.1
            (PeerRole::Server, "18f369389d126cfeecade20e1ea5ff9b", "curve25519-sha256,curve25519-sha256@libssh.org,curve448-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,ecdh-sha2-1.3.132.0.10,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group15-sha512,diffie-hellman-group16-sha512,diffie-hellman-group17-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256@ssh.com,diffie-hellman-group14-sha1,rsa2048-sha256,ext-info-c", "ssh-rsa", "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr", "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha256-2@ssh.com,hmac-sha224@ssh.com,hmac-sha256@ssh.com,hmac-sha384@ssh.com,hmac-sha512@ssh.com", "zlib@openssh.com,none"),
        ];

        for &(role, expected_hassh, kex, key, enc, mac, cmp) in vectors {
            let mut buf = vec![msg::KEXINIT];
            buf.extend_from_slice(&[0u8; 16]);
            kex.encode(&mut buf).unwrap();
            key.encode(&mut buf).unwrap();
            enc.encode(&mut buf).unwrap();
            enc.encode(&mut buf).unwrap();
            mac.encode(&mut buf).unwrap();
            mac.encode(&mut buf).unwrap();
            cmp.encode(&mut buf).unwrap();
            cmp.encode(&mut buf).unwrap();
            "".encode(&mut buf).unwrap();
            "".encode(&mut buf).unwrap();
            0u8.encode(&mut buf).unwrap();
            0u32.encode(&mut buf).unwrap();

            let offer = KexOffer::decode_kexinit(role, &buf).unwrap();
            assert_eq!(offer.hassh_algorithms(), format!("{kex};{enc};{mac};{cmp}"));
            assert_eq!(offer.hassh(), expected_hassh);
        }
    }
}

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Dropbear sends a wrong `first_kex_packet_follows` guess. Under strict kex the server
//! must ignore it and accept the real KEX_ECDH_INIT and NEWKEYS one sequence number later.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use russh::*;
use ssh_key::PrivateKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const KEXINIT: u8 = 20;
const NEWKEYS: u8 = 21;
const KEX_ECDH_INIT: u8 = 30;
const KEX_ECDH_REPLY: u8 = 31;

fn name_list(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s.as_bytes());
}

/// Client KEXINIT. Listing rsa first makes the guess wrong for a server with only an ed25519 key.
fn kexinit(follows: bool) -> Vec<u8> {
    let mut p = vec![KEXINIT];
    p.extend_from_slice(&[0u8; 16]);
    name_list(&mut p, "curve25519-sha256,kex-strict-c-v00@openssh.com");
    name_list(&mut p, "rsa-sha2-512,ssh-ed25519");
    for _ in 0..2 {
        name_list(&mut p, "chacha20-poly1305@openssh.com");
    }
    for _ in 0..2 {
        name_list(&mut p, "hmac-sha2-256");
    }
    for _ in 0..2 {
        name_list(&mut p, "none");
    }
    for _ in 0..2 {
        name_list(&mut p, "");
    }
    p.push(follows as u8);
    p.extend_from_slice(&0u32.to_be_bytes());
    p
}

fn ecdh_init() -> Vec<u8> {
    let mut p = vec![KEX_ECDH_INIT];
    p.extend_from_slice(&32u32.to_be_bytes());
    p.extend_from_slice(&rand::random::<[u8; 32]>());
    p
}

async fn send(stream: &mut TcpStream, payload: &[u8]) {
    let mut pad = 8 - (5 + payload.len()) % 8;
    if pad < 4 {
        pad += 8;
    }
    let mut pkt = ((1 + payload.len() + pad) as u32).to_be_bytes().to_vec();
    pkt.push(pad as u8);
    pkt.extend_from_slice(payload);
    pkt.resize(pkt.len() + pad, 0);
    stream.write_all(&pkt).await.unwrap();
}

/// Message type of the next packet, or `None` on EOF.
async fn recv(stream: &mut TcpStream) -> Option<u8> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await.ok()?;
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut body).await.ok()?;
    body.get(1).copied()
}

#[tokio::test]
async fn server_accepts_ignored_guess_under_strict_kex() {
    let _ = env_logger::try_init();

    let mut config = server::Config::default();
    config.inactivity_timeout = None;
    config
        .keys
        .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    config.preferred = Preferred {
        kex: Cow::Borrowed(&[kex::CURVE25519, kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER]),
        ..Default::default()
    };
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let (socket, _) = socket.accept().await.unwrap();
        let _ = server::run_stream(Arc::new(config), socket, TestServer).await;
    });

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(b"SSH-2.0-raw\r\n").await.unwrap();
    let mut id = [0u8; 1];
    loop {
        stream.read_exact(&mut id).await.unwrap();
        if id[0] == b'\n' {
            break;
        }
    }

    send(&mut stream, &kexinit(true)).await; // seqno 0
    send(&mut stream, &ecdh_init()).await; // seqno 1: wrong guess, ignored
    send(&mut stream, &ecdh_init()).await; // seqno 2: the real one

    let mut seen = vec![];
    while let Some(t) = recv(&mut stream).await {
        seen.push(t);
        if t == NEWKEYS {
            break;
        }
    }
    assert_eq!(seen, [KEXINIT, KEX_ECDH_REPLY, NEWKEYS]);

    send(&mut stream, &[NEWKEYS]).await; // seqno 3
    // The server now waits for encrypted traffic. An EOF means it rejected NEWKEYS.
    let eof = tokio::time::timeout(Duration::from_millis(500), stream.read(&mut id)).await;
    assert!(eof.is_err(), "server closed the connection: {eof:?}");
}

#[derive(Clone)]
struct TestServer;

impl server::Handler for TestServer {
    type Error = russh::Error;
}

// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use std::{borrow::Cow, fmt, str::FromStr, time::Duration};

use anyhow::Result;
use bech32::{self, primitives::decode::CheckedHrpstring, Hrp, NoChecksum};
use bhttp;
use nostr::{
    hashes::{sha256, Hash},
    secp256k1::rand::RngCore,
};
use nostr_sdk::prelude::*;
use ohttp::{self, KeyConfig};
use rand::rngs::OsRng;
use reqwest::{header::ACCEPT, Proxy};

pub fn decode(encoded: &str) -> (Hrp, Vec<u8>) {
    let hrp_string = CheckedHrpstring::new::<NoChecksum>(encoded).unwrap();
    (
        hrp_string.hrp(),
        hrp_string.byte_iter().collect::<Vec<u8>>(),
    )
}

const ENCAPSULATED_MESSAGE_BYTES: usize = 8192;
const N_ENC: usize = 65; // Un-compressed public key
const N_T: usize = 16;
const OHTTP_REQ_HEADER_BYTES: usize = 7;
const PADDED_BHTTP_REQ_BYTES: usize =
    ENCAPSULATED_MESSAGE_BYTES - (N_ENC + N_T + OHTTP_REQ_HEADER_BYTES);

const KEM_ID: &[u8] = b"\x00\x16"; // DHKEM(secp256k1, HKDF-SHA256)
const SYMMETRIC_LEN: &[u8] = b"\x00\x04"; // 4 bytes
const SYMMETRIC_KDF_AEAD: &[u8] = b"\x00\x01\x00\x03"; // KDF(HKDF-SHA256), AEAD(ChaCha20Poly1305)

#[derive(Debug, Clone)]
pub struct OhttpKeys(pub KeyConfig);

impl OhttpKeys {
    /// Decode an OHTTP KeyConfig
    pub fn decode(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        Ok(KeyConfig::decode(bytes).map(Self)?)
    }
}

impl TryFrom<&[u8]> for OhttpKeys {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let key_id = *bytes.first().ok_or(anyhow::anyhow!("invalid format"))?;
        let compressed_pk = bytes.get(1..34).ok_or(anyhow::anyhow!("invalid format"))?;

        let pubkey = secp256k1::PublicKey::from_slice(compressed_pk).unwrap();

        let mut buf = vec![key_id];
        buf.extend_from_slice(KEM_ID);
        buf.extend_from_slice(&pubkey.serialize_uncompressed());
        buf.extend_from_slice(SYMMETRIC_LEN);
        buf.extend_from_slice(SYMMETRIC_KDF_AEAD);

        Ok(ohttp::KeyConfig::decode(&buf).map(Self)?)
    }
}

impl std::str::FromStr for OhttpKeys {
    type Err = anyhow::Error;

    /// Parses a base64URL-encoded string into OhttpKeys.
    /// The string format is: key_id || compressed_public_key
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let oh_hrp: bech32::Hrp = bech32::Hrp::parse("OH").unwrap();

        let (hrp, bytes) = decode(s);

        if hrp != oh_hrp {
            return Err(anyhow::anyhow!("invalid format"));
        }

        Self::try_from(&bytes[..])
    }
}

pub fn ohttp_encapsulate(
    ohttp_keys: &mut KeyConfig,
    method: &str,
    target_resource: &str,
    body: String,
) -> Result<([u8; ENCAPSULATED_MESSAGE_BYTES], ohttp::ClientResponse), anyhow::Error> {
    use std::fmt::Write;
    let ctx = ohttp::ClientRequest::from_config(ohttp_keys)?;
    let mut url = url::Url::parse(&target_resource)?;
    println!("url: {:?}", url);
    let authority_bytes = url.host().map_or_else(Vec::new, |host| {
        let mut authority = host.to_string();
        if let Some(port) = url.port() {
            write!(authority, ":{port}").unwrap();
        }
        authority.into_bytes()
    });

    let path = format!("/?message={}", hex::encode(body.as_bytes()));

    let mut bhttp_message = bhttp::Message::request(
        method.as_bytes().to_vec(),
        url.scheme().as_bytes().to_vec(),
        authority_bytes,
        path.as_bytes().to_vec(),
    );
    // None of our messages include headers, so we don't add them
    if method != "GET" {
        bhttp_message.write_content(body.as_bytes());
    }

    let mut bhttp_req = [0u8; PADDED_BHTTP_REQ_BYTES];
    OsRng.fill_bytes(&mut bhttp_req);
    bhttp_message.write_bhttp(bhttp::Mode::KnownLength, &mut bhttp_req.as_mut_slice())?;
    let (encapsulated, ohttp_ctx) = ctx.encapsulate(&bhttp_req)?;

    let mut buffer = [0u8; ENCAPSULATED_MESSAGE_BYTES];
    let len = encapsulated.len().min(ENCAPSULATED_MESSAGE_BYTES);
    buffer[..len].copy_from_slice(&encapsulated[..len]);
    Ok((buffer, ohttp_ctx))
}

pub async fn fetch_ohttp_keys(
    ohttp_relay: String,
    target: String,
) -> Result<OhttpKeys, anyhow::Error> {
    // TODO: need to route this request from the relay to the target
    let target_url = url::Url::parse(&target)?.join("/ohttp-keys")?;
    let client = reqwest::Client::builder().build()?;
    let res = client
        .get(target_url)
        .header(ACCEPT, "application/ohttp-keys")
        .send()
        .await?;
    if !res.status().is_success() {
        println!("{res:#?}");
        return Err(anyhow::anyhow!("unexpected status code"));
    }

    let body = res.bytes().await?.to_vec();
    OhttpKeys::decode(&body).map_err(|e| anyhow::anyhow!("invalid ohttp keys: {}", e))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let ephemeral_key = Keys::generate();
    let target = "http://localhost:8080".to_string();
    let ohttp_relay = "http://localhost:3000".to_string();
    let mut key_config = fetch_ohttp_keys(ohttp_relay.clone(), target.clone()).await?;
    let client = reqwest::Client::new();
    println!("{key_config:#?}");

    let now = Timestamp::now();
    let event = EventBuilder::text_note(format!("foooo baar over OHTTP ! {now}"))
        .sign_with_keys(&ephemeral_key)
        .unwrap();

    let client_message = ClientMessage::Event(Cow::Borrowed(&event)).as_json();

    let (encapsulated, ohttp_ctx) =
        ohttp_encapsulate(&mut key_config.0, "POST", &target, client_message)?;

    let response = client
        .post(ohttp_relay.clone())
        .header("Content-Type", "message/ohttp-req")
        .body(encapsulated.to_vec())
        .send()
        .await?;
    // Test if we can decrypt the response
    let response_body = response.bytes().await?;
    let decapsulated = ohttp_ctx.decapsulate(&response_body)?;
    let str_res = String::from_utf8(decapsulated)?;
    println!("{str_res:#?}");

    let pk = ephemeral_key.public_key;
    let filter = Filter::new().author(pk).kind(Kind::TextNote);
    let subscription_id = SubscriptionId::generate();

    let client_message = ClientMessage::Req {
        subscription_id: Cow::Borrowed(&subscription_id),
        filter: Cow::Borrowed(&filter),
    }
    .as_json();
    let (encapsulated, ohttp_ctx) =
        ohttp_encapsulate(&mut key_config.0, "GET", &target, client_message)?;

    let response = client
        .post(ohttp_relay)
        .header("Content-Type", "message/ohttp-req")
        .body(encapsulated.to_vec())
        .send()
        .await?;
    println!("{response:#?}");

    let response_body = response.bytes().await?;

    let decapsulated = ohttp_ctx.decapsulate(&response_body)?;
    let str_res = String::from_utf8(decapsulated)?;
    let events = str_res
        .split("\n")
        .map(|s| Event::from_json(s))
        .filter_map(Result::ok)
        .collect::<Vec<Event>>();
    println!("{events:#?}");
    assert_eq!(events[0].id, event.id);

    Ok(())
}

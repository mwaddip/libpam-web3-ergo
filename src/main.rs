//! Ergo verification plugin for libpam-web3.
//!
//! Identity verification: derives the Ergo P2PK address from the compressed
//! secp256k1 public key in the .sig file and compares it against the GECOS
//! wallet address. The auth-svc has already validated structural correctness;
//! this plugin only binds key → address.
//!
//! # Protocol
//!
//! stdin:  {"sig": {chain, signature, public_key, otp, machine_id}, "otp_message": "...", "wallet_address": "..."}
//! stdout: Ergo address (Base58)
//! exit:   0 = verified, 1 = denied
//!
//! SPECIAL: S8 P10 E7 C5 I8 A8 L7 — authentication boundary

use blake2::digest::{consts::U32, Digest};
use blake2::Blake2b;

type Blake2b256 = Blake2b<U32>;
use serde::Deserialize;
use std::io::Read;
use std::process;

#[derive(Deserialize)]
struct PluginInput {
    sig: ErgoSig,
    #[allow(dead_code)]
    otp_message: String,
    wallet_address: String,
}

#[derive(Deserialize)]
struct ErgoSig {
    #[allow(dead_code)]
    chain: String,
    #[allow(dead_code)]
    signature: String,
    public_key: String,
    #[allow(dead_code)]
    otp: String,
    #[allow(dead_code)]
    machine_id: String,
}

#[derive(serde::Serialize)]
struct PluginInfoResponse {
    chain: &'static str,
    address_pattern: &'static str,
}

fn main() {
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("failed to read stdin: {}", e);
        process::exit(1);
    }

    // Info request — plugin discovery
    if let Ok(obj) = serde_json::from_str::<serde_json::Value>(&input) {
        if obj.get("command").and_then(|v| v.as_str()) == Some("info") {
            let info = PluginInfoResponse {
                chain: "ergo",
                // Matches mainnet P2PK (9...) and testnet P2PK (3...)
                // Base58 charset: [1-9A-HJ-NP-Za-km-z], P2PK addresses are 52 chars
                // (38 bytes: 1 type + 33 pubkey + 4 checksum → 52 Base58 chars)
                address_pattern: "^[39][1-9A-HJ-NP-Za-km-z]{51}$",
            };
            print!("{}", serde_json::to_string(&info).unwrap());
            process::exit(0);
        }
    }

    // Verify request
    let parsed: PluginInput = match serde_json::from_str(&input) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("invalid input JSON: {}", e);
            process::exit(1);
        }
    };

    match verify(&parsed) {
        Ok(address) => {
            print!("{}", address);
            process::exit(0);
        }
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    }
}

fn verify(input: &PluginInput) -> Result<String, String> {
    if input.sig.public_key.is_empty() {
        return Err("missing public_key".to_string());
    }
    if input.wallet_address.is_empty() {
        return Err("missing wallet_address".to_string());
    }

    // 1. Decode the compressed secp256k1 public key (33 bytes)
    let pubkey_bytes =
        hex::decode(&input.sig.public_key).map_err(|e| format!("invalid public_key hex: {}", e))?;

    if pubkey_bytes.len() != 33 {
        return Err(format!(
            "public_key must be 33 bytes (compressed secp256k1), got {}",
            pubkey_bytes.len()
        ));
    }

    // Validate compressed point prefix (0x02 or 0x03)
    if pubkey_bytes[0] != 0x02 && pubkey_bytes[0] != 0x03 {
        return Err(format!(
            "invalid compressed pubkey prefix: 0x{:02x} (expected 0x02 or 0x03)",
            pubkey_bytes[0]
        ));
    }

    // 2. Determine network from GECOS wallet address first character
    let type_byte: u8 = match input.wallet_address.as_bytes().first() {
        Some(b'9') => 0x01, // mainnet P2PK
        Some(b'3') => 0x11, // testnet P2PK
        Some(c) => {
            return Err(format!(
                "unrecognized Ergo address prefix: '{}' (expected '9' or '3')",
                *c as char
            ))
        }
        None => return Err("empty wallet_address".to_string()),
    };

    // 3. Build address: type_byte || pubkey || blake2b256(type_byte || pubkey)[0..4]
    let mut body = Vec::with_capacity(34);
    body.push(type_byte);
    body.extend_from_slice(&pubkey_bytes);

    let hash = Blake2b256::digest(&body);
    let checksum = &hash[..4];

    let mut full = Vec::with_capacity(38);
    full.extend_from_slice(&body);
    full.extend_from_slice(checksum);

    // 4. Base58-encode (no check variant — checksum is already appended)
    let derived_address = bs58::encode(&full).into_string();

    // 5. Compare with GECOS wallet address (case-sensitive, exact match)
    if derived_address != input.wallet_address {
        return Err("public key does not match wallet address".to_string());
    }

    // Identity confirmed — return the GECOS wallet address
    Ok(input.wallet_address.clone())
}

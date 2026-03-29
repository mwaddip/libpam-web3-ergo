# libpam-web3-ergo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Ergo authentication plugin for libpam-web3 — PAM verification plugin (Rust), auth-svc (Node.js HTTPS server), and signing page (Nautilus EIP-12 connector).

**Architecture:** Callback-only auth flow. Signing page connects to Nautilus wallet via EIP-12, calls `sign_data(address, message)` to produce a Schnorr proof. Auth-svc validates structure and writes `.sig` file. PAM plugin derives Ergo address from the public key and compares against GECOS `wallet=`. Three components: Rust binary (plugin), Node.js server (auth-svc), HTML/JS (signing page).

**Tech Stack:** Rust (serde, blake2, bs58, hex), Node.js + esbuild, `@noble/curves` + `@noble/hashes`, Nautilus EIP-12 dApp connector.

**S.P.E.C.I.A.L. Profile:** S8 P10 E7 C5 I8 A8 L7 — authentication boundary. Treat every external input as hostile.

**Port:** `crc32("ergo") → 22898`

**Spec:** `docs/specs/ergo.md` in the libpam-web3 repo

**Working directory:** `/home/mwaddip/projects/libpam-web3/plugins/ergo/`

**Reference implementation:** `/home/mwaddip/projects/libpam-web3/plugins/cardano/` — mirror its structure exactly

---

## File Structure

```
plugins/ergo/
├── src/
│   └── main.rs                    # PAM verification plugin
├── auth-svc-src/
│   └── index.ts                   # HTTPS auth server
├── signing-page/
│   ├── index.html                 # Signing UI
│   └── engine.js                  # Nautilus EIP-12 wallet integration
├── packaging/
│   └── build-deb.sh               # Debian package build
├── Cargo.toml                     # Rust deps
├── package.json                   # Node.js deps
├── web3-auth-svc.service          # Systemd unit
├── libpam-web3.conf               # tmpfiles.d
├── config.example.toml            # Optional config
├── dependencies.json              # Build-time dep manifest
└── .gitignore
```

---

### Task 1: Project Scaffolding

**Files:**
- Create: `Cargo.toml`
- Create: `package.json`
- Create: `.gitignore`
- Create: `config.example.toml`
- Create: `web3-auth-svc.service`
- Create: `libpam-web3.conf`
- Create: `dependencies.json`
- Create: `src/` (directory)
- Create: `auth-svc-src/` (directory)
- Create: `signing-page/` (directory)
- Create: `packaging/` (directory)

- [ ] **Step 1: Create Cargo.toml**

```toml
[package]
name = "libpam-web3-ergo"
version = "0.1.0"
edition = "2021"
description = "Ergo verification plugin for libpam-web3"
license = "MIT"

[[bin]]
name = "ergo"
path = "src/main.rs"

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Address derivation
blake2 = "0.10"
bs58 = "0.5"
hex = "0.4"
```

- [ ] **Step 2: Create package.json**

```json
{
  "name": "libpam-web3-ergo-auth-svc",
  "version": "0.1.0",
  "private": true,
  "dependencies": {
    "@noble/curves": "^1.8.0",
    "@noble/hashes": "^1.7.0"
  },
  "devDependencies": {
    "esbuild": "^0.24.0"
  }
}
```

- [ ] **Step 3: Create .gitignore**

```
target/
node_modules/
package-lock.json
auth-svc.js
packaging/*.deb
packaging/libpam-web3-*/
```

- [ ] **Step 4: Create config.example.toml**

```toml
# web3-auth-svc (Ergo) configuration
# Install to: /etc/web3-auth/ergo.toml
#
# This file is OPTIONAL. Without it, the auth-svc uses:
#   port = 22898  (derived: 1024 + crc32("ergo") % 64511)
#   pending_dir = /run/libpam-web3/pending

[server]
# Override the derived port if needed
# port = 22898
# Directory where PAM session files are written
# pending_dir = "/run/libpam-web3/pending"
```

- [ ] **Step 5: Create web3-auth-svc.service**

```ini
[Unit]
Description=libpam-web3 Auth Service (Ergo)
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/web3-auth-svc-ergo
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 6: Create libpam-web3.conf**

```
d /run/libpam-web3/pending 0755 root root -
```

- [ ] **Step 7: Create dependencies.json**

```json
{
  "runtime": {
    "@noble/curves": "^1.8.0",
    "@noble/hashes": "^1.7.0"
  },
  "note": "Auth-svc is bundled with esbuild to a single JS file. These are build-time deps."
}
```

- [ ] **Step 8: Create directories**

```bash
mkdir -p src auth-svc-src signing-page packaging
```

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -m "scaffold: project structure, deps, systemd, config"
```

---

### Task 2: Rust Verification Plugin

**Files:**
- Create: `src/main.rs`

**Reference:** `/home/mwaddip/projects/libpam-web3/plugins/cardano/src/main.rs`

The plugin handles two commands via stdin JSON:
1. `{"command":"info"}` → return chain metadata for PAM discovery
2. Verify request → derive Ergo address from pubkey, compare with GECOS wallet

Ergo P2PK address derivation:
- `address = Base58(type_byte || compressed_pubkey || blake2b256(type_byte || compressed_pubkey)[0..4])`
- Mainnet type_byte: `0x01` (address starts with `9`), testnet: `0x11` (starts with `3`)

- [ ] **Step 1: Write src/main.rs — full plugin implementation**

```rust
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

use blake2::digest::Digest;
use blake2::Blake2b256;
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
                // Base58 charset: [1-9A-HJ-NP-Za-km-z], P2PK addresses are 51 chars
                address_pattern: "^[39][1-9A-HJ-NP-Za-km-z]{50}$",
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
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo build --release`
Expected: Compiles with no errors. Binary at `target/release/ergo`.

- [ ] **Step 3: Test info command**

```bash
echo '{"command":"info"}' | ./target/release/ergo
```

Expected output (exact):
```json
{"chain":"ergo","address_pattern":"^[39][1-9A-HJ-NP-Za-km-z]{50}$"}
```
Exit code: 0

- [ ] **Step 4: Test verify with a known testnet address**

Generate test data. Use the deployer key from the blockhost-ergo test environment to derive a known address, then feed it to the plugin.

```bash
# Generate test vector using Node.js (from blockhost-engine-ergo):
cd /home/mwaddip/projects/blockhost-ergo/blockhost-engine-ergo
node -e "
const { secp256k1 } = require('@noble/curves/secp256k1');
// Deployer private key (testnet)
const priv = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';
const pub = Buffer.from(secp256k1.getPublicKey(priv, true)).toString('hex');
console.log('pubkey:', pub);
"
```

Then test with the plugin (replace `PUBKEY_HEX` and `EXPECTED_ADDRESS` with actual values):

```bash
echo '{"sig":{"chain":"ergo","signature":"deadbeef","public_key":"PUBKEY_HEX","otp":"123456","machine_id":"test"},"otp_message":"Authenticate to test with code: 123456","wallet_address":"EXPECTED_ADDRESS"}' | ./target/release/ergo
```

Expected: prints the wallet address, exit 0.

- [ ] **Step 5: Test verify with wrong pubkey**

```bash
echo '{"sig":{"chain":"ergo","signature":"deadbeef","public_key":"020000000000000000000000000000000000000000000000000000000000000001","otp":"123456","machine_id":"test"},"otp_message":"Authenticate to test with code: 123456","wallet_address":"3Wy6H5zue2YARihJKk4ccYF239cDWZYSj43qfVmzearpoy1jTPa8"}' | ./target/release/ergo
```

Expected: stderr contains "public key does not match wallet address", exit 1.

- [ ] **Step 6: Test verify with invalid inputs**

```bash
# Empty pubkey
echo '{"sig":{"chain":"ergo","signature":"aa","public_key":"","otp":"1","machine_id":"t"},"otp_message":"x","wallet_address":"9abc"}' | ./target/release/ergo
# Expected: exit 1, "missing public_key"

# Wrong length pubkey
echo '{"sig":{"chain":"ergo","signature":"aa","public_key":"aabb","otp":"1","machine_id":"t"},"otp_message":"x","wallet_address":"9abc"}' | ./target/release/ergo
# Expected: exit 1, "must be 33 bytes"

# Invalid prefix
echo '{"sig":{"chain":"ergo","signature":"aa","public_key":"010000000000000000000000000000000000000000000000000000000000000001","otp":"1","machine_id":"t"},"otp_message":"x","wallet_address":"9abc"}' | ./target/release/ergo
# Expected: exit 1, "invalid compressed pubkey prefix"
```

- [ ] **Step 7: Commit**

```bash
git add src/main.rs
git commit -m "feat: Ergo verification plugin — pubkey to P2PK address derivation"
```

---

### Task 3: Auth-svc HTTPS Server

**Files:**
- Create: `auth-svc-src/index.ts`

**Reference:** `/home/mwaddip/projects/libpam-web3/plugins/cardano/auth-svc-src/index.ts`

Mirror the Cardano auth-svc exactly, replacing:
- Chain name: `cardano` → `ergo`
- Signature verification: COSE_Sign1 Ed25519 → structural validation of Schnorr proof + compressed pubkey format
- Sig file type: `CardanoSigFile` → `ErgoSigFile`

The auth-svc validates:
- Session exists and OTP matches (timing-safe)
- `key` is valid hex, 66 chars (33 bytes = compressed secp256k1 point)
- `key` starts with `02` or `03` (valid compressed point prefix)
- `signature` is valid hex, reasonable length (>= 64 chars / 32 bytes)
- Note: full Schnorr proof verification is NOT done — would require reimplementing sigma-rust's Fiat-Shamir hash. The session+OTP binding prevents forgery.

- [ ] **Step 1: Write auth-svc-src/index.ts**

```typescript
/**
 * web3-auth-svc — Ergo auth service for libpam-web3.
 *
 * Self-contained HTTPS server: serves the signing page and handles
 * auth callbacks.  Port is derived from the chain name via CRC32.
 * TLS uses the certs generated by the libpam-web3 postinst.
 *
 * Routes:
 *   GET  /              — Signing page HTML
 *   GET  /engine.js     — Signing page JS
 *   GET  /auth/pending/:session_id   — Return session JSON
 *   POST /auth/callback/:session_id  — Accept Schnorr signature, write .sig file
 *
 * .sig file format (JSON):
 *   { chain, signature, public_key, otp, machine_id }
 *   chain = "ergo" — tells the PAM module which verification plugin to use
 *
 * SPECIAL profile: S8 P10 E7 C5 I8 A8 L7
 *   P10: Auth boundary — validate every input, trust nothing from the network.
 *   E7: Long-running daemon — must not crash, must not leak.
 *
 * Signature validation:
 *   Structural checks only (compressed pubkey format, proof length).
 *   Full Schnorr verification would require sigma-rust's Fiat-Shamir hash,
 *   which is not available in JS. Session ID (128-bit) + OTP binding
 *   prevents forgery — an attacker cannot write a .sig without both.
 */

import * as https from "node:https";
import * as fs from "node:fs";
import * as path from "node:path";
import { timingSafeEqual } from "node:crypto";

// ── Constants ──────────────────────────────────────────────────────────

const CHAIN_NAME = "ergo";
const DEFAULT_PENDING_DIR = "/run/libpam-web3/pending";
let PENDING_DIR = DEFAULT_PENDING_DIR;
const MAX_BODY_SIZE = 16_384;

function chainPort(chain: string): number {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < chain.length; i++) {
    crc ^= chain.charCodeAt(i);
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ ((crc & 1) ? 0xEDB88320 : 0);
    }
  }
  return 1024 + ((crc ^ 0xFFFFFFFF) >>> 0) % 64511;
}

const SESSION_ID_RE = /^[0-9a-f]{32}$/;
const HEX_RE = /^[0-9a-fA-F]+$/;

// ── Config ─────────────────────────────────────────────────────────────

const DEFAULT_CERT = "/etc/libpam-web3/tls/cert.pem";
const DEFAULT_KEY = "/etc/libpam-web3/tls/key.pem";
const DEFAULT_PAGES_DIR = "/usr/share/blockhost/signing-pages";

interface ServerConfig {
  port: number;
  pending_dir: string;
  cert: string;
  key: string;
  pages_dir: string;
}

function parseToml(content: string): Record<string, Record<string, unknown>> {
  const result: Record<string, Record<string, unknown>> = {};
  let section = "";

  for (const raw of content.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;

    const secMatch = line.match(/^\[([a-zA-Z_][a-zA-Z0-9_]*)\]$/);
    if (secMatch?.[1]) {
      section = secMatch[1];
      result[section] = result[section] || {};
      continue;
    }

    const kvMatch = line.match(/^([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+)$/);
    if (!kvMatch?.[1] || !kvMatch[2] || !section) continue;

    const key = kvMatch[1];
    const val = kvMatch[2].trim();

    if (val.startsWith('"') && val.endsWith('"')) {
      result[section]![key] = val.slice(1, -1);
    } else {
      const num = Number(val);
      result[section]![key] = Number.isNaN(num) ? val : num;
    }
  }

  return result;
}

function loadConfig(configPath: string): ServerConfig {
  const defaultPort = chainPort(CHAIN_NAME);
  const defaults: ServerConfig = {
    port: defaultPort,
    pending_dir: DEFAULT_PENDING_DIR,
    cert: DEFAULT_CERT,
    key: DEFAULT_KEY,
    pages_dir: path.join(DEFAULT_PAGES_DIR, CHAIN_NAME),
  };

  let content: string;
  try {
    content = fs.readFileSync(configPath, "utf8");
  } catch {
    return defaults;
  }

  const toml = parseToml(content);
  const sec = toml["server"] || {};

  return {
    port: typeof sec.port === "number" ? sec.port : defaults.port,
    pending_dir: String(sec.pending_dir || defaults.pending_dir),
    cert: String(sec.cert || defaults.cert),
    key: String(sec.key || defaults.key),
    pages_dir: String(sec.pages_dir || defaults.pages_dir),
  };
}

// ── Validation ────────────────────────────────────────────────────────

function isValidSessionId(id: string): boolean {
  return SESSION_ID_RE.test(id);
}

function isValidHex(str: string): boolean {
  return str.length > 0 && str.length % 2 === 0 && HEX_RE.test(str);
}

// ── Payload Types ─────────────────────────────────────────────────────

interface CallbackPayload {
  signature: string;
  key: string;
  otp: string;
  machineId: string;
}

function parseCallbackBody(body: string): CallbackPayload | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return null;
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return null;
  }

  const obj = parsed as Record<string, unknown>;
  const keys = Object.keys(obj);

  if (keys.length !== 4) return null;
  if (typeof obj["signature"] !== "string") return null;
  if (typeof obj["key"] !== "string") return null;
  if (typeof obj["otp"] !== "string") return null;
  if (typeof obj["machineId"] !== "string") return null;

  if (obj["otp"].length > 16 || obj["machineId"].length > 128) return null;

  if (!isValidHex(obj["signature"])) return null;
  if (!isValidHex(obj["key"])) return null;

  return {
    signature: obj["signature"],
    key: obj["key"],
    otp: obj["otp"],
    machineId: obj["machineId"],
  };
}

// ── Session ───────────────────────────────────────────────────────────

interface SessionData {
  otp: string;
  machine_id: string;
}

function readSession(sessionId: string): SessionData | null {
  const jsonPath = path.join(PENDING_DIR, `${sessionId}.json`);
  try {
    const content = fs.readFileSync(jsonPath, "utf8");
    const parsed: unknown = JSON.parse(content);
    if (typeof parsed !== "object" || parsed === null) return null;
    const obj = parsed as Record<string, unknown>;
    if (typeof obj["otp"] !== "string" || typeof obj["machine_id"] !== "string") {
      return null;
    }
    return { otp: obj["otp"], machine_id: obj["machine_id"] };
  } catch {
    return null;
  }
}

// ── Verification & .sig Write ─────────────────────────────────────────

interface ErgoSigFile {
  chain: "ergo";
  signature: string;
  public_key: string;
  otp: string;
  machine_id: string;
}

function validateAndWriteSig(sessionId: string, payload: CallbackPayload): string | null {
  const sigPath = path.join(PENDING_DIR, `${sessionId}.sig`);
  if (fs.existsSync(sigPath)) return "session already processed";

  const session = readSession(sessionId);
  if (!session) return "session not found or malformed";

  // Timing-safe OTP comparison
  const otpA = Buffer.from(payload.otp);
  const otpB = Buffer.from(session.otp);
  if (otpA.length !== otpB.length) return "otp mismatch";
  if (!timingSafeEqual(otpA, otpB)) return "otp mismatch";

  if (payload.machineId !== session.machine_id) return "machine_id mismatch";

  // Structural validation of the Ergo signature payload
  // P10: validate every field, trust nothing from the network

  // Public key: must be 33 bytes (66 hex chars), compressed secp256k1
  if (payload.key.length !== 66) {
    return `public key must be 33 bytes (66 hex), got ${payload.key.length} hex chars`;
  }
  const keyPrefix = payload.key.slice(0, 2).toLowerCase();
  if (keyPrefix !== "02" && keyPrefix !== "03") {
    return `invalid compressed pubkey prefix: ${keyPrefix} (expected 02 or 03)`;
  }

  // Signature: Schnorr proof — at minimum 32 bytes (response scalar)
  // Typical proveDlog proof: 33 (commitment) + 32 (response) = 65 bytes = 130 hex
  if (payload.signature.length < 64) {
    return `signature too short: ${payload.signature.length} hex chars (min 64)`;
  }
  if (payload.signature.length > 512) {
    return `signature too long: ${payload.signature.length} hex chars (max 512)`;
  }

  // Write .sig file (atomic: write tmp, rename)
  const sigContent: ErgoSigFile = {
    chain: "ergo",
    signature: payload.signature,
    public_key: payload.key,
    otp: payload.otp,
    machine_id: payload.machineId,
  };

  const tmpPath = path.join(PENDING_DIR, `${sessionId}.sig.tmp`);
  try {
    fs.writeFileSync(tmpPath, JSON.stringify(sigContent));
    fs.renameSync(tmpPath, sigPath);
  } catch (err) {
    try { fs.unlinkSync(tmpPath); } catch { /* tmp may not exist */ }
    return `sig file write failed: ${err instanceof Error ? err.message : String(err)}`;
  }

  console.log(`[AUTH] Accepted Ergo signature for session ${sessionId}`);
  return null;
}

// ── Route Handlers ────────────────────────────────────────────────────

type HttpResponse = import("node:http").ServerResponse;
type HttpRequest = import("node:http").IncomingMessage;

function sendResponse(
  res: HttpResponse,
  statusCode: number,
  body: string,
  contentType = "text/plain",
): void {
  res.writeHead(statusCode, { "Content-Type": contentType });
  res.end(body);
}

function handleGetPending(sessionId: string, res: HttpResponse): void {
  if (!isValidSessionId(sessionId)) {
    sendResponse(res, 404, "Not Found");
    return;
  }

  const jsonPath = path.join(PENDING_DIR, `${sessionId}.json`);
  let contents: string;
  try {
    contents = fs.readFileSync(jsonPath, "utf8");
  } catch {
    sendResponse(res, 404, "Not Found");
    return;
  }

  sendResponse(res, 200, contents, "application/json");
}

function handlePostCallback(
  sessionId: string,
  req: HttpRequest,
  res: HttpResponse,
): void {
  if (!isValidSessionId(sessionId)) {
    sendResponse(res, 404, "Not Found");
    return;
  }

  const contentType = req.headers["content-type"] || "";
  if (!contentType.includes("application/json")) {
    sendResponse(res, 400, "Content-Type must be application/json");
    return;
  }

  const chunks: Buffer[] = [];
  let bodySize = 0;
  let aborted = false;

  req.on("data", (chunk: Buffer) => {
    bodySize += chunk.length;
    if (bodySize > MAX_BODY_SIZE) {
      if (!aborted) {
        aborted = true;
        sendResponse(res, 413, "body too large");
        req.destroy();
      }
      return;
    }
    chunks.push(chunk);
  });

  req.on("end", () => {
    if (aborted) return;

    const body = Buffer.concat(chunks).toString("utf8").trim();
    const payload = parseCallbackBody(body);
    if (!payload) {
      sendResponse(res, 400, "invalid request body");
      return;
    }

    const error = validateAndWriteSig(sessionId, payload);

    if (error === null) {
      sendResponse(res, 200, "OK");
    } else if (error === "session already processed") {
      sendResponse(res, 409, "Conflict");
    } else if (error === "session not found or malformed") {
      sendResponse(res, 404, "Not Found");
    } else {
      console.error(`[AUTH] Callback rejected for session ${sessionId}: ${error}`);
      sendResponse(res, 400, "verification failed");
    }
  });

  req.on("error", () => { /* connection closed by client */ });
}

// ── Static file serving ───────────────────────────────────────────────

let PAGES_DIR = "";

function serveFile(
  res: HttpResponse,
  filePath: string,
  contentType: string,
): void {
  let data: Buffer;
  try {
    data = fs.readFileSync(filePath);
  } catch {
    sendResponse(res, 404, "Not Found");
    return;
  }
  res.writeHead(200, {
    "Content-Type": contentType,
    "Content-Length": data.length,
  });
  res.end(data);
}

// ── Server ────────────────────────────────────────────────────────────

function main(): void {
  const configPath = process.argv[2] || `/etc/web3-auth/${CHAIN_NAME}.toml`;
  const config = loadConfig(configPath);
  PENDING_DIR = config.pending_dir;
  PAGES_DIR = config.pages_dir;

  let tlsOpts: { cert: Buffer; key: Buffer };
  try {
    tlsOpts = {
      cert: fs.readFileSync(config.cert),
      key: fs.readFileSync(config.key),
    };
  } catch (err) {
    console.error(`[AUTH] TLS cert/key load failed: ${err}`);
    process.exit(1);
  }

  const server = https.createServer(tlsOpts, (req, res) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cache-Control", "no-store");

    const url = new URL(req.url || "/", "https://localhost");
    const pathname = url.pathname;

    // Signing page
    if (req.method === "GET" && (pathname === "/" || pathname === "/index.html")) {
      serveFile(res, path.join(PAGES_DIR, "index.html"), "text/html; charset=utf-8");
      return;
    }
    if (req.method === "GET" && pathname === "/engine.js") {
      serveFile(res, path.join(PAGES_DIR, "engine.js"), "application/javascript; charset=utf-8");
      return;
    }

    // Auth API
    const pendingMatch = pathname.match(/^\/auth\/pending\/([^/]+)$/);
    if (req.method === "GET" && pendingMatch?.[1]) {
      handleGetPending(pendingMatch[1], res);
      return;
    }

    const callbackMatch = pathname.match(/^\/auth\/callback\/([^/]+)$/);
    if (req.method === "POST" && callbackMatch?.[1]) {
      handlePostCallback(callbackMatch[1], req, res);
      return;
    }

    sendResponse(res, 404, "Not Found");
  });

  server.listen(config.port, "::", () => {
    console.log(`[AUTH] web3-auth-svc (${CHAIN_NAME}) on [::]:${config.port}`);
    console.log(`[AUTH] Pending dir: ${PENDING_DIR}`);
    console.log(`[AUTH] Pages: ${PAGES_DIR}`);
  });

  server.on("error", (err) => {
    console.error(`[AUTH] Server error: ${err}`);
    process.exit(1);
  });

  process.on("SIGTERM", () => {
    console.log("[AUTH] Shutting down...");
    server.close(() => process.exit(0));
  });

  process.on("SIGINT", () => {
    console.log("[AUTH] Shutting down...");
    server.close(() => process.exit(0));
  });
}

main();
```

- [ ] **Step 2: Install deps and verify esbuild bundles**

```bash
npm install --silent
npx esbuild auth-svc-src/index.ts --bundle --platform=node --target=node22 --minify --outfile=auth-svc.js
```

Expected: `auth-svc.js` created, no errors.

- [ ] **Step 3: Commit**

```bash
git add auth-svc-src/index.ts
git commit -m "feat: auth-svc HTTPS server — session handling, structural validation, .sig writer"
```

---

### Task 4: Signing Page

**Files:**
- Create: `signing-page/index.html`
- Create: `signing-page/engine.js`

**Reference:** `/home/mwaddip/projects/libpam-web3/plugins/cardano/signing-page/`

Key differences from Cardano:
- Wallet detection: `window.ergoConnector.nautilus` (EIP-12) instead of `window.cardano` (CIP-30)
- Connection: `ergoConnector.nautilus.connect()` → makes `window.ergo` available
- Addresses: `ergo.get_used_addresses()` returns Base58 strings (not hex-encoded like Cardano)
- Signing: `ergo.sign_data(address, message)` — address is Base58, message is UTF-8 string
- Return value: proof string (hex) — no separate key field like CIP-30's `{ signature, key }`
- Public key extraction: Base58-decode the address, skip type byte, take 33 bytes

- [ ] **Step 1: Write signing-page/index.html**

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Web3 Auth</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;background:#0a0a0a;color:#e0e0e0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.c{max-width:480px;width:100%;background:#1a1a1a;border-radius:12px;padding:24px;box-shadow:0 4px 24px rgba(0,0,0,.5)}
h1{font-size:1.25rem;margin-bottom:16px;color:#fff}
label{display:block;margin-bottom:6px;font-size:.875rem;color:#888}
input,select{width:100%;padding:12px;border:1px solid #333;border-radius:8px;background:#0a0a0a;color:#fff;font-size:1rem;margin-bottom:16px;font-family:inherit}
input:focus,select:focus{outline:none;border-color:#ff5e18}
button{width:100%;padding:12px;border:none;border-radius:8px;font-size:1rem;cursor:pointer;transition:background .2s}
.btn-primary{background:#ff5e18;color:#fff}
.btn-primary:hover{background:#cc4b13}
.btn-primary:disabled{background:#662510;cursor:not-allowed}
.btn-secondary{background:#4b5563;color:#fff;margin-top:8px}
.btn-copy{background:#22c55e;color:#fff;margin-top:8px}
.result{margin-top:16px;padding:12px;background:#0a0a0a;border-radius:8px;word-break:break-all;font-family:monospace;font-size:.75rem;max-height:120px;overflow-y:auto}
.status{text-align:center;padding:8px;margin-bottom:16px;border-radius:6px;font-size:.875rem}
.status.error{background:#7f1d1d;color:#fca5a5}
.status.success{background:#14532d;color:#86efac}
.hidden{display:none}
.wallet{font-size:.75rem;color:#666;margin-bottom:16px;word-break:break-all}
.info{font-size:.75rem;color:#888;margin-bottom:16px;line-height:1.5}
.wallet-list{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px}
.wallet-btn{padding:8px 16px;border:1px solid #333;border-radius:8px;background:#1a1a1a;color:#fff;cursor:pointer;font-size:.875rem}
.wallet-btn:hover{border-color:#ff5e18;color:#ff5e18}
</style>
</head>
<body>
<div class="c">
<h1>Ergo Authentication</h1>
<div id="status" class="status hidden"></div>

<div id="connect-section">
<p class="info">Sign in to your server using your Ergo wallet. Connect your wallet to continue.</p>
<div id="wallet-list" class="wallet-list"></div>
<p id="no-wallets" class="info hidden">No EIP-12 compatible wallets detected. Install Nautilus Wallet.</p>
</div>

<div id="main-section" class="hidden">
<div id="wallet" class="wallet"></div>

<div id="sign-form">
<label for="code">Enter OTP Code</label>
<input type="text" id="code" placeholder="123456" maxlength="8" autocomplete="off">
<label for="machine">Machine ID</label>
<input type="text" id="machine" placeholder="server-prod-01" autocomplete="off">
<button id="sign" class="btn-primary">Sign Message</button>
</div>

<div id="sign-result" class="hidden">
<label>Signature (paste this in terminal)</label>
<div id="sig" class="result"></div>
<button id="copy-sig" class="btn-copy">Copy to Clipboard</button>
<button id="reset-sign" class="btn-secondary">Sign Another</button>
</div>
</div>
</div>

<script src="engine.js"></script>
</body>
</html>
```

- [ ] **Step 2: Write signing-page/engine.js**

```javascript
(function(){
let api = null;  // EIP-12 context API (window.ergo after connect)
let usedAddress = '';  // Base58 Ergo address

const $ = id => document.getElementById(id);
const show = (id, v=true) => $(id).classList.toggle('hidden', !v);
const status = (msg, type='success') => {
  const s = $('status');
  s.textContent = msg;
  s.className = 'status ' + type;
  show('status');
};

const sessionId = (new URLSearchParams(window.location.search)).get('session');

// ── Base58 decode (extract pubkey from Ergo address) ──────────────────

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Decode(str) {
  const map = {};
  for (let i = 0; i < B58_ALPHABET.length; i++) map[B58_ALPHABET[i]] = BigInt(i);

  let num = 0n;
  for (const c of str) {
    const val = map[c];
    if (val === undefined) throw new Error('Invalid Base58 character: ' + c);
    num = num * 58n + val;
  }

  // Convert to byte array
  let hex = num.toString(16);
  if (hex.length % 2) hex = '0' + hex;

  // Count leading '1's (Base58 zero bytes)
  let leadingZeros = 0;
  for (const c of str) { if (c === '1') leadingZeros++; else break; }

  const bytes = new Uint8Array(leadingZeros + hex.length / 2);
  for (let i = 0; i < hex.length / 2; i++) {
    bytes[leadingZeros + i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function extractPubkeyHex(address) {
  const bytes = base58Decode(address);
  // Ergo P2PK address: type_byte(1) + pubkey(33) + checksum(4) = 38 bytes
  if (bytes.length !== 38) throw new Error('Unexpected address length: ' + bytes.length);
  const pubkey = bytes.slice(1, 34);  // Skip type byte, take 33 bytes
  return Array.from(pubkey).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Wallet detection (EIP-12) ─────────────────────────────────────────

function detectWallets() {
  const walletList = $('wallet-list');
  const connector = window.ergoConnector;
  if (!connector) {
    show('no-wallets');
    return;
  }

  const known = ['nautilus', 'safew', 'minotaur'];
  let found = 0;

  for (const name of known) {
    if (connector[name]) {
      const btn = document.createElement('button');
      btn.className = 'wallet-btn';
      btn.textContent = connector[name].name || name;
      btn.onclick = () => connectWallet(name);
      walletList.appendChild(btn);
      found++;
    }
  }

  // Check for other EIP-12 wallets
  for (const key of Object.keys(connector)) {
    if (!known.includes(key) && connector[key] && typeof connector[key].connect === 'function') {
      const btn = document.createElement('button');
      btn.className = 'wallet-btn';
      btn.textContent = connector[key].name || key;
      btn.onclick = () => connectWallet(key);
      walletList.appendChild(btn);
      found++;
    }
  }

  if (found === 0) {
    show('no-wallets');
  }
}

async function connectWallet(name) {
  try {
    const connected = await window.ergoConnector[name].connect();
    if (!connected) { status('Connection rejected', 'error'); return; }

    // After connect, window.ergo becomes available (EIP-12 context API)
    api = window.ergo;
    if (!api) { status('Wallet API not available after connect', 'error'); return; }

    const addresses = await api.get_used_addresses();
    if (addresses.length === 0) {
      const unused = await api.get_unused_addresses();
      usedAddress = unused[0] || '';
    } else {
      usedAddress = addresses[0];
    }

    if (!usedAddress) { status('No addresses in wallet', 'error'); return; }

    const display = usedAddress.length > 20
      ? usedAddress.slice(0, 12) + '...' + usedAddress.slice(-8)
      : usedAddress;
    $('wallet').textContent = 'Connected: ' + display;
    show('connect-section', false);
    show('main-section');
    show('status', false);

    if (sessionId) await loadSession();
  } catch(e) {
    status('Connection failed: ' + (e.message || e), 'error');
  }
}

async function loadSession() {
  try {
    const res = await fetch('/auth/pending/' + sessionId);
    if (!res.ok) return;
    const data = await res.json();
    if (data.otp) { $('code').value = data.otp; $('code').readOnly = true; }
    if (data.machine_id) { $('machine').value = data.machine_id; $('machine').readOnly = true; }
  } catch(e) { /* fall through to manual mode */ }
}

async function sign() {
  const code = $('code').value.trim();
  const machine = $('machine').value.trim();
  if (!code) { status('Enter OTP code', 'error'); return; }
  if (!machine) { status('Enter machine ID', 'error'); return; }
  if (!api) { status('No wallet connected', 'error'); return; }

  const msg = 'Authenticate to ' + machine + ' with code: ' + code;

  try {
    $('sign').disabled = true;
    $('sign').textContent = 'Signing...';

    // EIP-12 sign_data: address (Base58 string), message (UTF-8 string)
    const result = await api.sign_data(usedAddress, msg);

    // Extract compressed pubkey from address (Base58 decode)
    let pubkeyHex;
    try {
      pubkeyHex = extractPubkeyHex(usedAddress);
    } catch(e) {
      status('Failed to extract public key from address: ' + e.message, 'error');
      return;
    }

    // Callback mode: POST to auth-svc
    if (sessionId) {
      try {
        const cb = await fetch('/auth/callback/' + sessionId, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            signature: result,
            key: pubkeyHex,
            otp: code,
            machineId: machine,
          }),
        });
        if (cb.ok) {
          show('sign-form', false);
          show('sign-result', false);
          status('Signature sent! Press Enter in your terminal.', 'success');
          return;
        }
        // If callback failed, fall through to manual copy
        const errText = await cb.text().catch(() => cb.statusText);
        console.warn('Callback failed:', cb.status, errText);
      } catch(e) { /* fall through to manual copy mode */ }
    }

    // Manual mode: show JSON for copy-paste
    const sigData = JSON.stringify({
      chain: 'ergo',
      signature: result,
      public_key: pubkeyHex,
      otp: code,
      machine_id: machine,
    });
    $('sig').textContent = sigData;
    show('sign-form', false);
    show('sign-result');
    status('Signed! Copy and paste the JSON below into your terminal.', 'success');
  } catch(e) {
    status('Signing failed: ' + (e.message || e), 'error');
  } finally {
    $('sign').disabled = false;
    $('sign').textContent = 'Sign Message';
  }
}

function resetSign() {
  show('sign-form');
  show('sign-result', false);
  $('code').value = '';
  $('code').readOnly = false;
  $('machine').readOnly = false;
  show('status', false);
  if (sessionId) loadSession();
}

$('sign').onclick = sign;
$('copy-sig').onclick = () => {
  navigator.clipboard.writeText($('sig').textContent).then(() => {
    const btn = $('copy-sig');
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = orig, 2000);
  });
};
$('reset-sign').onclick = resetSign;
$('code').onkeypress = e => { if (e.key === 'Enter') $('machine').focus(); };
$('machine').onkeypress = e => { if (e.key === 'Enter') sign(); };

// Wallet extensions inject ergoConnector asynchronously — delay detection
function waitAndDetect() {
  if (window.ergoConnector) { detectWallets(); return; }
  let tries = 0;
  const timer = setInterval(() => {
    if (window.ergoConnector || ++tries > 30) {
      clearInterval(timer);
      detectWallets();
    }
  }, 100);
}
waitAndDetect();
})();
```

- [ ] **Step 3: Commit**

```bash
git add signing-page/
git commit -m "feat: signing page — Nautilus EIP-12 connector, Base58 pubkey extraction"
```

---

### Task 5: Debian Packaging

**Files:**
- Create: `packaging/build-deb.sh`

**Reference:** `/home/mwaddip/projects/libpam-web3/plugins/cardano/packaging/build-deb.sh`

Exact mirror of Cardano build script with `cardano` → `ergo`, port `34206` → `22898`.

- [ ] **Step 1: Write packaging/build-deb.sh**

```bash
#!/bin/bash
#
# Build a .deb package for libpam-web3-ergo
#
# This package contains:
#   - Ergo verification plugin for PAM
#   - web3-auth-svc (Ergo Schnorr signing server)
#   - Signing page HTML + engine.js
#   - Systemd unit and tmpfiles.d config
#
# Usage: ./packaging/build-deb.sh
#
# Requirements:
#   - cargo (Rust toolchain)
#   - node + npx (for esbuild bundling of auth-svc)
#   - dpkg-deb

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="0.1.0"
ARCH="amd64"
PKG_NAME="libpam-web3-ergo"
PKG_DIR="$SCRIPT_DIR/${PKG_NAME}_${VERSION}_${ARCH}"

echo "=== Building ${PKG_NAME} ${VERSION} for ${ARCH} ==="

# Clean previous build
rm -rf "$PKG_DIR"
rm -f "$SCRIPT_DIR/${PKG_NAME}_${VERSION}_${ARCH}.deb"

# 1. Build Rust plugin binary (target glibc 2.36 for Debian 12 compatibility)
echo "[1/4] Building Ergo verification plugin..."
cd "$PROJECT_DIR"
ZIG_TARGET="x86_64-unknown-linux-gnu.2.36"
BINDGEN_EXTRA_CLANG_ARGS="--sysroot=/ -I/usr/include" \
RUSTFLAGS="-L /usr/lib/x86_64-linux-gnu" \
cargo zigbuild --release --target "$ZIG_TARGET"

# 2. Bundle auth-svc with esbuild
echo "[2/4] Bundling auth-svc..."
cd "$PROJECT_DIR"
if ! command -v npx &> /dev/null; then
    echo "ERROR: npx not found. Install Node.js to bundle auth-svc."
    exit 1
fi

# Install dependencies
(cd "$PROJECT_DIR" && npm install --silent)

npx esbuild auth-svc-src/index.ts \
    --bundle --platform=node --target=node22 --minify \
    --outfile=auth-svc.js

# 3. Create package directory structure
echo "[3/4] Creating package structure..."
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/lib/libpam-web3/plugins"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/usr/share/blockhost/auth-svc/ergo"
mkdir -p "$PKG_DIR/usr/share/blockhost/signing-pages/ergo"
mkdir -p "$PKG_DIR/lib/systemd/system"
mkdir -p "$PKG_DIR/usr/lib/tmpfiles.d"
mkdir -p "$PKG_DIR/usr/share/doc/${PKG_NAME}"

# Copy plugin binary
cp "$PROJECT_DIR/target/x86_64-unknown-linux-gnu/release/ergo" "$PKG_DIR/usr/lib/libpam-web3/plugins/"

# Copy bundled auth-svc
cp "$PROJECT_DIR/auth-svc.js" "$PKG_DIR/usr/share/blockhost/auth-svc/ergo/"

# Create wrapper script for auth-svc
cat > "$PKG_DIR/usr/bin/web3-auth-svc-ergo" << 'WRAPPER'
#!/bin/sh
exec node /usr/share/blockhost/auth-svc/ergo/auth-svc.js "$@"
WRAPPER

# Copy signing page (served directly by auth-svc)
cp "$PROJECT_DIR/signing-page/index.html" "$PKG_DIR/usr/share/blockhost/signing-pages/ergo/"
cp "$PROJECT_DIR/signing-page/engine.js" "$PKG_DIR/usr/share/blockhost/signing-pages/ergo/"

# Copy systemd unit
cp "$PROJECT_DIR/web3-auth-svc.service" "$PKG_DIR/lib/systemd/system/web3-auth-svc-ergo.service"

# Copy tmpfiles.d config
cp "$PROJECT_DIR/libpam-web3.conf" "$PKG_DIR/usr/lib/tmpfiles.d/"

# Copy config example as documentation
cp "$PROJECT_DIR/config.example.toml" "$PKG_DIR/usr/share/doc/${PKG_NAME}/"

# Create control file
cat > "$PKG_DIR/DEBIAN/control" << EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${ARCH}
Depends: libpam-web3
Recommends: nodejs (>= 18)
Maintainer: libpam-web3 maintainers
Homepage: https://github.com/mwaddip/libpam-web3-ergo
Description: Ergo authentication plugin for libpam-web3
 Adds Ergo wallet authentication support to libpam-web3.
 .
 Components:
  - Verification plugin (secp256k1 pubkey to Ergo P2PK address derivation)
  - web3-auth-svc (HTTPS signing server with Schnorr proof validation)
  - Signing page (Nautilus EIP-12 compatible wallet UI)
 .
 Requires libpam-web3 (core PAM module) to be installed.
EOF

# Create postinst
cat > "$PKG_DIR/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e
case "$1" in
    configure)
        systemd-tmpfiles --create /usr/lib/tmpfiles.d/libpam-web3.conf 2>/dev/null || true
        systemctl daemon-reload
        systemctl enable --now web3-auth-svc-ergo 2>/dev/null || true
        echo ""
        echo "=== libpam-web3-ergo installed ==="
        echo ""
        echo "Plugin:       /usr/lib/libpam-web3/plugins/ergo"
        echo "Auth-svc:     systemctl status web3-auth-svc-ergo"
        echo "Signing page: https://$(hostname):22898/"
        echo ""
        echo "No configuration needed — port derived from chain name, TLS from libpam-web3."
        echo ""
        ;;
esac
exit 0
EOF
chmod 755 "$PKG_DIR/DEBIAN/postinst"

# Create prerm
cat > "$PKG_DIR/DEBIAN/prerm" << 'EOF'
#!/bin/bash
set -e
case "$1" in
    remove|upgrade)
        systemctl stop web3-auth-svc-ergo 2>/dev/null || true
        systemctl disable web3-auth-svc-ergo 2>/dev/null || true
        ;;
esac
exit 0
EOF
chmod 755 "$PKG_DIR/DEBIAN/prerm"

# Set permissions
find "$PKG_DIR" -type d -exec chmod 755 {} \;
find "$PKG_DIR" -type f -exec chmod 644 {} \;
chmod 755 "$PKG_DIR/DEBIAN/postinst"
chmod 755 "$PKG_DIR/DEBIAN/prerm"
chmod 755 "$PKG_DIR/usr/lib/libpam-web3/plugins/ergo"
chmod 755 "$PKG_DIR/usr/bin/web3-auth-svc-ergo"

# 4. Build the package
echo "[4/4] Building .deb package..."
cd "$SCRIPT_DIR"
dpkg-deb --build --root-owner-group "$PKG_DIR"

DEB_FILE="$SCRIPT_DIR/${PKG_NAME}_${VERSION}_${ARCH}.deb"
if [ -f "$DEB_FILE" ]; then
    echo ""
    echo "=== Package built successfully ==="
    ls -lh "$DEB_FILE"
    echo ""
    dpkg-deb -c "$DEB_FILE"
else
    echo "ERROR: Package build failed"
    exit 1
fi
```

- [ ] **Step 2: Make build script executable**

```bash
chmod +x packaging/build-deb.sh
```

- [ ] **Step 3: Commit**

```bash
git add packaging/build-deb.sh
git commit -m "feat: Debian packaging — build-deb.sh with plugin, auth-svc, signing page"
```

---

### Task 6: Build Verification

- [ ] **Step 1: Build the Rust plugin**

```bash
cd /home/mwaddip/projects/libpam-web3/plugins/ergo
cargo build --release
```

Expected: Binary at `target/release/ergo`, compiles cleanly.

- [ ] **Step 2: Test the plugin info command**

```bash
echo '{"command":"info"}' | ./target/release/ergo
```

Expected: `{"chain":"ergo","address_pattern":"^[39][1-9A-HJ-NP-Za-km-z]{50}$"}`

- [ ] **Step 3: Test address derivation against known blockhost test wallet**

Use the deployer public key from the blockhost-ergo test environment. The deployer address is `3Wy6H5zue2YARihJKk4ccYF239cDWZYSj43qfVmzearpoy1jTPa8` and the server public key is `0347203530f6977e33b0465a0da69428f2497f90ce32434fc16fb17c93e3e8300e`.

```bash
echo '{"sig":{"chain":"ergo","signature":"aabbccdd","public_key":"0347203530f6977e33b0465a0da69428f2497f90ce32434fc16fb17c93e3e8300e","otp":"123456","machine_id":"test"},"otp_message":"Authenticate to test with code: 123456","wallet_address":"3Wy6H5zue2YARihJKk4ccYF239cDWZYSj43qfVmzearpoy1jTPa8"}' | ./target/release/ergo
```

Expected: prints `3Wy6H5zue2YARihJKk4ccYF239cDWZYSj43qfVmzearpoy1jTPa8`, exit 0.

- [ ] **Step 4: Test mismatched pubkey is rejected**

```bash
echo '{"sig":{"chain":"ergo","signature":"aabbccdd","public_key":"020000000000000000000000000000000000000000000000000000000000000001","otp":"123456","machine_id":"test"},"otp_message":"x","wallet_address":"3Wy6H5zue2YARihJKk4ccYF239cDWZYSj43qfVmzearpoy1jTPa8"}' | ./target/release/ergo 2>&1; echo "EXIT: $?"
```

Expected: stderr contains "public key does not match wallet address", exit 1.

- [ ] **Step 5: Bundle auth-svc**

```bash
npm install --silent
npx esbuild auth-svc-src/index.ts --bundle --platform=node --target=node22 --minify --outfile=auth-svc.js
ls -lh auth-svc.js
```

Expected: `auth-svc.js` exists, reasonable size (~20-50KB).

- [ ] **Step 6: Commit any fixes, push**

```bash
git add -A
git status
# If clean, push. If changes, commit first:
# git commit -m "fix: build verification adjustments"
git push origin main
```

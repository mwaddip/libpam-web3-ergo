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

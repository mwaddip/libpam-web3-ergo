/**
 * Signing page engine — Ergo EIP-12 (Nautilus / SAFEW / Minotaur) authentication.
 *
 * Self-initializes on DOMContentLoaded. Reads configuration from the global
 * CONFIG object (injected by the generator). Finds required DOM elements by
 * ID per the page template interface contract.
 *
 * Required DOM element IDs:
 *   btn-connect, btn-sign, wallet-address, status-message,
 *   step-connect, step-sign
 *
 * Extra (template-allowed) IDs used:
 *   wallet-list — populated with per-wallet buttons after btn-connect click
 *   code, machine — readonly display of OTP / machine_id from session
 *
 * CSS classes toggled by this bundle:
 *   hidden, active, completed, disabled, loading, error, success
 */
(function () {
  'use strict';

  // ── Helpers ──────────────────────────────────────────────────────────

  function $(id) { return document.getElementById(id); }

  // ── Status management ───────────────────────────────────────────────

  function setStatus(msg, type) {
    var el = $('status-message');
    if (!el) return;
    el.textContent = msg;
    el.classList.remove('hidden', 'error', 'success');
    if (type) el.classList.add(type);
    if (!msg) el.classList.add('hidden');
  }

  function clearStatus() {
    var el = $('status-message');
    if (!el) return;
    el.textContent = '';
    el.classList.add('hidden');
    el.classList.remove('error', 'success');
  }

  // ── Step state management ───────────────────────────────────────────

  function activateStep(stepId) {
    var el = $(stepId);
    if (!el) return;
    el.classList.remove('hidden', 'completed');
    el.classList.add('active');
  }

  function completeStep(stepId) {
    var el = $(stepId);
    if (!el) return;
    el.classList.remove('active', 'hidden');
    el.classList.add('completed');
  }

  // ── Button state ────────────────────────────────────────────────────

  function setButtonLoading(btn, loading) {
    if (!btn) return;
    if (loading) {
      btn.classList.add('loading', 'disabled');
      btn.disabled = true;
    } else {
      btn.classList.remove('loading', 'disabled');
      btn.disabled = false;
    }
  }

  // ── Base58 → 33-byte compressed pubkey extraction ───────────────────
  //
  // An Ergo P2PK address is base58(typeByte || pubkey || checksum) where
  // pubkey is the 33-byte compressed secp256k1 point. The auth-svc needs
  // the pubkey in hex to verify the Schnorr proof, so we recover it
  // client-side from the address the wallet hands us.

  var B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

  function base58Decode(str) {
    var map = {};
    for (var i = 0; i < B58_ALPHABET.length; i++) map[B58_ALPHABET[i]] = BigInt(i);

    var num = 0n;
    for (var c = 0; c < str.length; c++) {
      var val = map[str[c]];
      if (val === undefined) throw new Error('Invalid Base58 character: ' + str[c]);
      num = num * 58n + val;
    }

    var hex = num.toString(16);
    if (hex.length % 2) hex = '0' + hex;

    var leadingZeros = 0;
    for (var d = 0; d < str.length; d++) { if (str[d] === '1') leadingZeros++; else break; }

    var bytes = new Uint8Array(leadingZeros + hex.length / 2);
    for (var k = 0; k < hex.length / 2; k++) {
      bytes[leadingZeros + k] = parseInt(hex.slice(k * 2, k * 2 + 2), 16);
    }
    return bytes;
  }

  function extractPubkeyHex(address) {
    var bytes = base58Decode(address);
    // typeByte(1) + pubkey(33) + checksum(4) = 38 bytes
    if (bytes.length !== 38) throw new Error('Unexpected address length: ' + bytes.length);
    var pubkey = bytes.slice(1, 34);
    var hex = '';
    for (var i = 0; i < pubkey.length; i++) hex += ('0' + pubkey[i].toString(16)).slice(-2);
    return hex;
  }

  // ── Wallet detection (EIP-12) ───────────────────────────────────────

  var KNOWN_WALLETS = ['nautilus', 'safew', 'minotaur'];

  function detectWallets() {
    var connector = window.ergoConnector;
    if (!connector) return [];

    var found = [];
    var seen = {};

    for (var i = 0; i < KNOWN_WALLETS.length; i++) {
      var name = KNOWN_WALLETS[i];
      if (connector[name] && typeof connector[name].connect === 'function') {
        found.push({ key: name, label: connector[name].name || name });
        seen[name] = true;
      }
    }

    var keys = Object.keys(connector);
    for (var j = 0; j < keys.length; j++) {
      var k = keys[j];
      if (!seen[k] && connector[k] && typeof connector[k].connect === 'function') {
        found.push({ key: k, label: connector[k].name || k });
      }
    }

    return found;
  }

  // Wallet extensions inject ergoConnector asynchronously. Resolve once it
  // appears, or after a short bounded retry window if it never does.
  function waitForConnector() {
    return new Promise(function (resolve) {
      if (window.ergoConnector) return resolve();
      var tries = 0;
      var timer = setInterval(function () {
        if (window.ergoConnector || ++tries > 30) {
          clearInterval(timer);
          resolve();
        }
      }, 100);
    });
  }

  // ── Main logic ──────────────────────────────────────────────────────

  function init() {
    var btnConnect = $('btn-connect');
    var btnSign = $('btn-sign');
    var walletAddress = $('wallet-address');
    var walletList = $('wallet-list');
    var codeEl = $('code');
    var machineEl = $('machine');

    var sessionId = (new URLSearchParams(window.location.search)).get('session');

    if (!sessionId) {
      setStatus('No session. Use the link from your terminal.', 'error');
      if (btnConnect) {
        btnConnect.disabled = true;
        btnConnect.classList.add('disabled');
      }
      return;
    }

    activateStep('step-connect');

    var api = null;          // EIP-12 context API (window.ergo after connect)
    var usedAddress = '';    // base58 Ergo P2PK address
    var otp = '';
    var machineId = '';

    function loadSession() {
      fetch('/auth/pending/' + sessionId).then(function (res) {
        if (!res.ok) { setStatus('Session not found or expired', 'error'); return; }
        return res.json();
      }).then(function (data) {
        if (!data) return;
        otp = data.otp || '';
        machineId = data.machine_id || '';
        if (codeEl) codeEl.value = otp;
        if (machineEl) machineEl.value = machineId;
      }).catch(function () {
        setStatus('Failed to load session', 'error');
      });
    }

    function showWalletPicker() {
      waitForConnector().then(function () {
        var wallets = detectWallets();
        if (wallets.length === 0) {
          setStatus('No EIP-12 wallets detected. Install Nautilus.', 'error');
          return;
        }

        while (walletList.firstChild) walletList.removeChild(walletList.firstChild);

        for (var i = 0; i < wallets.length; i++) {
          var w = wallets[i];
          var btn = document.createElement('button');
          btn.className = 'wallet-btn';
          btn.textContent = w.label;
          btn.dataset.wallet = w.key;
          btn.onclick = (function (key) {
            return function () { connectWallet(key); };
          })(w.key);
          walletList.appendChild(btn);
        }

        btnConnect.classList.add('hidden');
        walletList.classList.remove('hidden');
      });
    }

    function connectWallet(name) {
      setStatus('Connecting to ' + name + '...', '');

      window.ergoConnector[name].connect().then(function (connected) {
        if (!connected) throw new Error('Connection rejected');
        api = window.ergo;
        if (!api) throw new Error('Wallet API not available after connect');
        return api.get_used_addresses();
      }).then(function (addresses) {
        if (addresses && addresses.length) {
          usedAddress = addresses[0];
          return null;
        }
        return api.get_unused_addresses();
      }).then(function (unused) {
        if (unused && unused.length) usedAddress = unused[0];
        if (!usedAddress) throw new Error('No addresses in wallet');

        if (walletAddress) walletAddress.textContent = usedAddress;
        completeStep('step-connect');
        activateStep('step-sign');
        clearStatus();
        loadSession();
      }).catch(function (e) {
        setStatus('Connection failed: ' + (e.message || e), 'error');
      });
    }

    function sign() {
      if (!api) { setStatus('No wallet connected', 'error'); return; }
      if (!otp || !machineId) { setStatus('Session data incomplete', 'error'); return; }

      var pubkeyHex;
      try {
        pubkeyHex = extractPubkeyHex(usedAddress);
      } catch (e) {
        setStatus('Failed to extract public key from address: ' + e.message, 'error');
        return;
      }

      var msg = 'Authenticate to ' + machineId + ' with code: ' + otp;

      setButtonLoading(btnSign, true);

      api.sign_data(usedAddress, msg).then(function (signatureHex) {
        var payload = JSON.stringify({
          signature: signatureHex,
          key: pubkeyHex,
          otp: otp,
          machineId: machineId,
        });

        return fetch('/auth/callback/' + sessionId, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: payload,
        });
      }).then(function (cb) {
        if (cb.ok) {
          completeStep('step-sign');
          setStatus('Signature sent! Press Enter in your terminal.', 'success');
        } else {
          setStatus('Server rejected the signature (' + cb.status + ')', 'error');
        }
      }).catch(function (e) {
        setStatus('Signing failed: ' + (e.message || e), 'error');
      }).finally(function () {
        setButtonLoading(btnSign, false);
      });
    }

    if (btnConnect) btnConnect.onclick = showWalletPicker;
    if (btnSign) btnSign.onclick = sign;
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

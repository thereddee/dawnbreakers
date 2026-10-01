// Unlocks the DM Only page: derives a key from the password and decrypts
// window.DM_PAYLOAD (written by build.mjs). A wrong password fails the GCM check.
(function () {
  const form = document.getElementById('lock-form');
  const input = document.getElementById('lock-input');
  const button = form.querySelector('button');
  const error = document.getElementById('lock-error');
  const lock = document.getElementById('lock');
  const vault = document.getElementById('vault');
  const STORAGE_KEY = 'dawnbreakers-dm-key';

  const bytes = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

  async function decrypt(password) {
    const p = window.DM_PAYLOAD;
    const material = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: bytes(p.salt), iterations: p.iter, hash: 'SHA-256' },
      material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes(p.iv) }, key, bytes(p.ct));
    return new TextDecoder().decode(plain);
  }

  async function open(password, quiet) {
    if (!window.crypto || !crypto.subtle) {
      error.textContent = 'This page must be opened over https.';
      return;
    }
    button.disabled = true;
    try {
      vault.innerHTML = await decrypt(password);
      lock.hidden = true;
      vault.hidden = false;
      try { sessionStorage.setItem(STORAGE_KEY, password); } catch (e) { /* storage unavailable */ }
    } catch (e) {
      if (!quiet) error.textContent = 'The Guardian does not know your touch.';
    } finally {
      button.disabled = false;
    }
  }

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    error.textContent = '';
    open(input.value.replace(/[\s-]/g, ''), false);
  });

  let remembered = null;
  try { remembered = sessionStorage.getItem(STORAGE_KEY); } catch (e) { /* storage unavailable */ }
  if (remembered) open(remembered, true);
})();

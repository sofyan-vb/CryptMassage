/**
 * ChronoCrypt - Secure Message Cipher & Decryption Studio
 * 1:1 Proportional Reversible Cipher (Permanent, No Expiration)
 */

// --- Cipher Engine ---
const MASTER_KEY = 'CHRONOCRYPT_SECURE_PERMANENT_KEY';

// Derive 32 rolling character offsets from key
function getKeyOffsets(keyStr = MASTER_KEY) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < keyStr.length; i++) {
    hash ^= keyStr.charCodeAt(i);
    hash = (hash * 0x01000193) >>> 0;
  }
  const offsets = [];
  let state = hash;
  for (let i = 0; i < 32; i++) {
    state = (state * 1664525 + 1013904223) >>> 0;
    offsets.push((state % 25) + 1); // Shift 1..25
  }
  return offsets;
}

// 2-character validation checksum
function computeChecksum(text, keyStr = MASTER_KEY) {
  let sum = 0;
  for (let i = 0; i < text.length; i++) {
    sum = (sum * 31 + text.charCodeAt(i)) >>> 0;
  }
  for (let i = 0; i < keyStr.length; i++) {
    sum = (sum * 37 + keyStr.charCodeAt(i)) >>> 0;
  }
  const c1 = String.fromCharCode(97 + (sum % 26));
  const c2 = String.fromCharCode(97 + ((sum >>> 5) % 26));
  return `${c1}${c2}`;
}

// 1:1 Character transformation (proportional length, preserving casing and symbols)
function transformText(text, offsets, decrypt = false) {
  let charIdx = 0;
  return text.split('').map(ch => {
    const isUpper = ch >= 'A' && ch <= 'Z';
    const isLower = ch >= 'a' && ch <= 'z';
    const isDigit = ch >= '0' && ch <= '9';

    if (!isUpper && !isLower && !isDigit) {
      return ch;
    }

    const shift = offsets[charIdx % offsets.length] * (decrypt ? -1 : 1);
    charIdx++;

    if (isLower) {
      const code = ch.charCodeAt(0) - 97;
      const res = (code + shift) % 26;
      return String.fromCharCode(97 + (res < 0 ? res + 26 : res));
    }
    if (isUpper) {
      const code = ch.charCodeAt(0) - 65;
      const res = (code + shift) % 26;
      return String.fromCharCode(65 + (res < 0 ? res + 26 : res));
    }
    if (isDigit) {
      const code = ch.charCodeAt(0) - 48;
      const res = (code + shift) % 10;
      return String.fromCharCode(48 + (res < 0 ? res + 10 : res));
    }
    return ch;
  }).join('');
}

// Encrypt message permanently (no expiration)
function encryptMessage(text) {
  const offsets = getKeyOffsets(MASTER_KEY);
  const scrambled = transformText(text, offsets, false);
  const tag = computeChecksum(text, MASTER_KEY);
  return `${scrambled}~${tag}`;
}

// Decrypt message with verification and legacy slot fallback
function decryptMessage(cipherWithTag) {
  const clean = cipherWithTag.trim();
  if (!clean) {
    throw new Error('Empty cipher text');
  }

  const lastTilde = clean.lastIndexOf('~');
  let cipherText = clean;
  let expectedTag = null;

  if (lastTilde !== -1 && lastTilde < clean.length - 1) {
    cipherText = clean.substring(0, lastTilde);
    let meta = clean.substring(lastTilde + 1);
    if (meta.includes('.')) {
      meta = meta.split('.')[1];
    }
    expectedTag = meta;
  }

  // 1. Attempt decryption using permanent MASTER_KEY
  const offsets = getKeyOffsets(MASTER_KEY);
  const decrypted = transformText(cipherText, offsets, true);

  if (expectedTag) {
    const calculatedTag = computeChecksum(decrypted, MASTER_KEY);
    if (calculatedTag === expectedTag) {
      return decrypted;
    }

    // 2. Fallback check for any legacy time-slotted messages so old tests still work
    const legacyDecrypted = tryLegacyDecryption(cipherText, expectedTag);
    if (legacyDecrypted !== null) {
      return legacyDecrypted;
    }

    throw new Error('Decryption failed: Checksum mismatch or corrupted text.');
  }

  return decrypted;
}

// Legacy fallback helper for previously encrypted time-slot tokens
function tryLegacyDecryption(cipherText, expectedTag) {
  const now = Date.now();
  const durations = ['1h', '15m', '24h'];
  // Check slots spanning back up to 7 days
  for (let h = 0; h <= 168; h++) {
    const testDate = new Date(now - h * 3600000);
    const y = testDate.getUTCFullYear();
    const m = String(testDate.getUTCMonth() + 1).padStart(2, '0');
    const d = String(testDate.getUTCDate()).padStart(2, '0');
    const hr = String(testDate.getUTCHours()).padStart(2, '0');

    for (const dur of durations) {
      let slotKey = `KEY-${y}${m}${d}-H${hr}`;
      if (dur === '24h') slotKey = `KEY-${y}${m}${d}-DAY`;
      if (dur === '15m') {
        const startMin = Math.floor(testDate.getUTCMinutes() / 15) * 15;
        slotKey = `KEY-${y}${m}${d}-H${hr}M${String(startMin).padStart(2, '0')}`;
      }

      const legacyOffsets = getKeyOffsets(slotKey);
      const testDecrypted = transformText(cipherText, legacyOffsets, true);
      if (computeChecksum(testDecrypted, slotKey) === expectedTag) {
        return testDecrypted;
      }
    }
  }
  return null;
}

// Scramble animation effect during processing
function animateScramble(textarea, finalString, duration = 240) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789#%&*@!';
  const startTime = Date.now();
  const len = finalString.length;

  const timer = setInterval(() => {
    const elapsed = Date.now() - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const resolved = Math.floor(progress * len);

    let output = '';
    for (let i = 0; i < len; i++) {
      if (i < resolved) {
        output += finalString[i];
      } else {
        output += chars[Math.floor(Math.random() * chars.length)];
      }
    }
    textarea.value = output;

    if (progress >= 1) {
      clearInterval(timer);
      textarea.value = finalString;
    }
  }, 30);
}

// --- DOM References ---
// Tabs
const tabEncryptBtn = document.getElementById('tabEncryptBtn');
const tabDecryptBtn = document.getElementById('tabDecryptBtn');
const encryptSection = document.getElementById('encryptSection');
const decryptSection = document.getElementById('decryptSection');

// Encrypt Controls
const encryptInput = document.getElementById('encryptInput');
const encryptCharCount = document.getElementById('encryptCharCount');
const btnEncrypt = document.getElementById('btnEncrypt');
const btnClearEncrypt = document.getElementById('btnClearEncrypt');
const encryptOutputWrapper = document.getElementById('encryptOutputWrapper');
const encryptOutput = document.getElementById('encryptOutput');
const btnCopyEncrypted = document.getElementById('btnCopyEncrypted');
const btnSendToDecrypt = document.getElementById('btnSendToDecrypt');

// Decrypt Controls
const decryptInput = document.getElementById('decryptInput');
const btnDecrypt = document.getElementById('btnDecrypt');
const btnClearDecrypt = document.getElementById('btnClearDecrypt');
const decryptErrorAlert = document.getElementById('decryptErrorAlert');
const decryptErrorText = document.getElementById('decryptErrorText');
const decryptOutputWrapper = document.getElementById('decryptOutputWrapper');
const decryptOutput = document.getElementById('decryptOutput');
const btnCopyDecrypted = document.getElementById('btnCopyDecrypted');

// Privacy Blur Elements
const btnToggleBlur = document.getElementById('btnToggleBlur');
const blurToggleText = document.getElementById('blurToggleText');
let isPrivacyBlurred = false;

// Toast Notification
const toast = document.getElementById('toast');
const toastMsg = document.getElementById('toastMsg');

function showToast(message) {
  toastMsg.textContent = message;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2000);
}

// --- Tab Switching ---
function switchTab(target) {
  if (target === 'encrypt') {
    tabEncryptBtn.classList.add('active');
    tabDecryptBtn.classList.remove('active');
    encryptSection.classList.add('active');
    decryptSection.classList.remove('active');
  } else {
    tabDecryptBtn.classList.add('active');
    tabEncryptBtn.classList.remove('active');
    decryptSection.classList.add('active');
    encryptSection.classList.remove('active');
  }
}

tabEncryptBtn.addEventListener('click', () => switchTab('encrypt'));
tabDecryptBtn.addEventListener('click', () => switchTab('decrypt'));

// --- Encrypt Handlers ---
encryptInput.addEventListener('input', () => {
  const len = encryptInput.value.length;
  encryptCharCount.textContent = `${len} ${len === 1 ? 'character' : 'characters'}`;
});

encryptInput.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    e.preventDefault();
    btnEncrypt.click();
  }
});

btnEncrypt.addEventListener('click', () => {
  const text = encryptInput.value.trim();
  if (!text) {
    showToast('Please enter a message first');
    encryptInput.focus();
    return;
  }

  const encrypted = encryptMessage(text);
  encryptOutputWrapper.classList.remove('hidden');
  animateScramble(encryptOutput, encrypted, 240);
  showToast('Message encrypted successfully');
});

btnClearEncrypt.addEventListener('click', () => {
  encryptInput.value = '';
  encryptCharCount.textContent = '0 characters';
  encryptOutput.value = '';
  encryptOutputWrapper.classList.add('hidden');
  encryptInput.focus();
  showToast('Form cleared');
});

btnCopyEncrypted.addEventListener('click', () => {
  if (!encryptOutput.value) return;
  navigator.clipboard.writeText(encryptOutput.value).then(() => {
    showToast('Cipher text copied to clipboard');
  }).catch(() => {
    encryptOutput.select();
    document.execCommand('copy');
    showToast('Cipher text copied to clipboard');
  });
});

btnSendToDecrypt.addEventListener('click', () => {
  if (!encryptOutput.value) return;
  decryptInput.value = encryptOutput.value;
  switchTab('decrypt');
  showToast('Transferred to Decrypt form');
});

// --- Decrypt Handlers ---
decryptInput.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    e.preventDefault();
    btnDecrypt.click();
  }
});

btnDecrypt.addEventListener('click', () => {
  const cipherText = decryptInput.value.trim();
  if (!cipherText) {
    showToast('Please paste cipher text first');
    decryptInput.focus();
    return;
  }

  decryptErrorAlert.classList.add('hidden');
  decryptOutputWrapper.classList.add('hidden');

  try {
    const decrypted = decryptMessage(cipherText);
    decryptOutputWrapper.classList.remove('hidden');
    animateScramble(decryptOutput, decrypted, 240);
    showToast('Message decrypted successfully');
  } catch (err) {
    decryptErrorAlert.classList.remove('hidden');
    decryptErrorText.textContent = 'Decryption failed: Invalid cipher text or corrupted message.';
    showToast('Decryption failed');
  }
});

btnClearDecrypt.addEventListener('click', () => {
  decryptInput.value = '';
  decryptOutput.value = '';
  decryptErrorAlert.classList.add('hidden');
  decryptOutputWrapper.classList.add('hidden');
  decryptInput.focus();
  showToast('Form cleared');
});

btnCopyDecrypted.addEventListener('click', () => {
  if (!decryptOutput.value) return;
  navigator.clipboard.writeText(decryptOutput.value).then(() => {
    showToast('Original message copied to clipboard');
  }).catch(() => {
    decryptOutput.select();
    document.execCommand('copy');
    showToast('Original message copied to clipboard');
  });
});

// --- Privacy Blur (Anti-Peeking Mode) ---
btnToggleBlur.addEventListener('click', () => {
  isPrivacyBlurred = !isPrivacyBlurred;
  if (isPrivacyBlurred) {
    decryptOutput.classList.add('blurred');
    btnToggleBlur.classList.add('active');
    blurToggleText.textContent = 'Unblur';
    showToast('Privacy blur enabled');
  } else {
    decryptOutput.classList.remove('blurred');
    btnToggleBlur.classList.remove('active');
    blurToggleText.textContent = 'Blur';
    showToast('Privacy blur disabled');
  }
});

// Click blurred textarea to reveal
decryptOutput.addEventListener('click', () => {
  if (isPrivacyBlurred) {
    btnToggleBlur.click();
  }
});

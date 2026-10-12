import { parseDesKey, generateRandomKey, deriveKeyFromPassphrase, bytesToHex, hexToBytes, generateKeyfileContent, parseKeyfileContent } from './crypto/des/keyManager.js';
import { createVaultContainer, inspectVaultContainer, openVaultContainer, sanitizeFilename } from './crypto/des/container.js';
import { calculateEntropy } from './crypto/des/entropy.js';
import { computeSHA256 } from './crypto/des/hash.js';
import { traceBlockEncryption, encryptBlock, decryptBlock } from './crypto/des/desCore.js';
import { generateKeyScheduleTrace } from './crypto/des/keySchedule.js';
import { encryptECB, encryptCBC, MODE_CBC, MODE_ECB } from './crypto/des/modes.js';
import { runAllTests } from './crypto/des/testVectors.js';
import { getHistory, addHistoryEntry, clearHistory, getVaultStats } from './services/historyManager.js';
import { SAMPLE_FILES, SAMPLE_TEXTS } from './services/samples.js';
import { generateKeyQRCodeSVG } from './services/qrGenerator.js';
import { encryptTextNote, decryptTextNote } from './services/textEncryption.js';

// DOM selector helper
const $ = (id) => document.getElementById(id);

// Application State
const state = {
  activeView: 'dashboard',
  encryptContentType: 'file', // 'file' | 'text'
  decryptContentType: 'file', // 'file' | 'text'
  textOutputFormat: 'base64',  // 'base64' | 'hex'
  encryptFile: null,          // { file, data: Uint8Array, name, type, size, hashHex, entropy }
  encryptKeyFormat: 'ascii',  // 'ascii' | 'hex' | 'passphrase'
  encryptMode: MODE_CBC,
  encryptedResult: null,      // { containerBytes, filename, originalHashHex, originalSize, mode, keyBytes, keyHex }
  encryptedTextResult: null,  // { formattedOutput, hashHex, entropy, mode }
  decryptFile: null,          // { file, data: Uint8Array, inspection }
  decryptedResult: null,      // { restoredData, filename, extension, mimeType, hashHex }
  decryptedTextResult: null,  // { plainText, charCount, byteCount, hashHex }
  currentKeyText: '',
  demoCurrentStep: 0
};

// Format utilities
function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function timeAgo(timestamp) {
  const diffSec = Math.floor((Date.now() - timestamp) / 1000);
  if (diffSec < 60) return 'Just now';
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return new Date(timestamp).toLocaleDateString();
}

// ==========================================
// VIEW NAVIGATION
// ==========================================
function switchView(viewName) {
  state.activeView = viewName;
  document.querySelectorAll('.view-container').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active'));

  const targetView = $(`view-${viewName}`);
  const targetNav = $(`nav-${viewName}`);

  if (targetView) targetView.classList.add('active');
  if (targetNav) targetNav.classList.add('active');

  window.scrollTo({ top: 0, behavior: 'smooth' });

  if (viewName === 'dashboard') updateDashboardStats();
  if (viewName === 'history') renderHistoryTable();
  if (viewName === 'lab') runDefaultLabSim();
}

// Navigation event bindings
document.querySelectorAll('.nav-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const view = btn.dataset.view;
    if (view) switchView(view);
  });
});

$('brand-home').addEventListener('click', () => switchView('dashboard'));
$('brand-home').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') {
    e.preventDefault();
    switchView('dashboard');
  }
});
$('dash-btn-encrypt').addEventListener('click', () => {
  state.encryptContentType = 'file';
  switchView('encrypt');
});
$('dash-btn-encrypt-text')?.addEventListener('click', () => switchView('text'));
$('dash-click-text-enc')?.addEventListener('click', () => switchView('text'));

$('dash-btn-decrypt').addEventListener('click', () => {
  state.decryptContentType = 'file';
  switchView('decrypt');
});
$('dash-btn-decrypt-text')?.addEventListener('click', () => switchView('text'));
$('dash-click-text-dec')?.addEventListener('click', () => switchView('text'));

// ==========================================
// DASHBOARD & SAMPLES
// ==========================================
function updateDashboardStats() {
  const stats = getVaultStats();
  $('stat-encrypted').textContent = stats.encryptedCount;
  $('stat-decrypted').textContent = stats.decryptedCount;
  $('stat-bytes').textContent = formatBytes(stats.totalBytesProcessed);

  if (stats.lastOperation) {
    $('stat-last-op').textContent = `${stats.lastOperation.operation}: ${stats.lastOperation.filename.slice(0, 16)}`;
    $('stat-last-time').textContent = timeAgo(stats.lastOperation.timestamp);
  } else {
    $('stat-last-op').textContent = 'None';
    $('stat-last-time').textContent = 'Awaiting operation';
  }
}

function renderSampleChips() {
  const container = $('sample-files-container');
  if (!container) return;
  container.innerHTML = '';

  // 1. Secret Text Note Samples (Direct to Text Vault)
  SAMPLE_TEXTS.forEach(sample => {
    const chip = document.createElement('div');
    chip.className = 'sample-file-chip';
    chip.style.borderColor = 'rgba(6, 182, 212, 0.45)';
    chip.innerHTML = `
      <span class="sample-chip-icon">${sample.icon}</span>
      <div class="sample-chip-info">
        <span class="sample-chip-name">${sample.name}</span>
        <span class="sample-chip-meta">${sample.typeDescription} (Text)</span>
      </div>
    `;
    chip.addEventListener('click', () => {
      loadTextIntoVault(sample.text);
      switchView('text');
    });
    container.appendChild(chip);
  });

  // 2. Binary File Samples (Direct to File Encryptor)
  SAMPLE_FILES.forEach(sample => {
    const chip = document.createElement('div');
    chip.className = 'sample-file-chip';
    chip.innerHTML = `
      <span class="sample-chip-icon">📄</span>
      <div class="sample-chip-info">
        <span class="sample-chip-name">${sample.name}</span>
        <span class="sample-chip-meta">${sample.typeDescription}</span>
      </div>
    `;
    chip.addEventListener('click', async () => {
      const data = sample.getData();
      await loadFileForEncryption({
        name: sample.name,
        type: sample.mimeType,
        size: data.length,
        lastModified: Date.now()
      }, data);
      switchView('encrypt');
    });
    container.appendChild(chip);
  });
}

// Dashboard quick drag-and-drop
function setupDashboardQuickDrops() {
  const dropEnc = $('dash-drop-encrypt');
  const dropDec = $('dash-drop-decrypt');

  const addDrag = (el, onFile) => {
    el.addEventListener('dragover', (e) => { e.preventDefault(); el.classList.add('drag-over'); });
    el.addEventListener('dragleave', () => el.classList.remove('drag-over'));
    el.addEventListener('drop', async (e) => {
      e.preventDefault();
      el.classList.remove('drag-over');
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        await onFile(e.dataTransfer.files[0]);
      }
    });
    el.addEventListener('click', () => {
      // route directly
      if (el === dropEnc) switchView('encrypt');
      else switchView('decrypt');
    });
  };

  addDrag(dropEnc, async (file) => {
    const buffer = await file.arrayBuffer();
    await loadFileForEncryption(file, new Uint8Array(buffer));
    switchView('encrypt');
  });

  addDrag(dropDec, async (file) => {
    const buffer = await file.arrayBuffer();
    await loadFileForDecryption(file, new Uint8Array(buffer));
    switchView('decrypt');
  });
}

// ==========================================
// ENCRYPT WORKFLOW
// ==========================================
async function loadFileForEncryption(file, uint8Data) {
  state.encryptFile = {
    file,
    data: uint8Data,
    name: sanitizeFilename(file.name),
    type: file.type || 'application/octet-stream',
    size: uint8Data.length
  };

  // UI Updates
  $('encrypt-dropzone').style.display = 'none';
  $('card-encrypt-file-selected').style.display = 'flex';
  $('card-encrypt-dna').style.display = 'block';
  $('encrypt-success-box').style.display = 'none';
  $('encrypt-journey-box').classList.remove('active');

  const ext = state.encryptFile.name.includes('.') ? state.encryptFile.name.split('.').pop().toUpperCase() : 'BIN';
  $('encrypt-file-ext-badge').textContent = ext.slice(0, 4);
  $('encrypt-file-name').textContent = state.encryptFile.name;
  $('encrypt-file-type').textContent = `MIME: ${state.encryptFile.type}`;
  $('encrypt-file-size').textContent = `${formatBytes(state.encryptFile.size)} (${state.encryptFile.size.toLocaleString()} bytes)`;
  $('encrypt-file-date').textContent = file.lastModified ? new Date(file.lastModified).toLocaleDateString() : 'Just now';

  // Compute File DNA telemetry
  $('dna-encrypt-hash').textContent = 'Computing SHA-256...';
  const { hex: hashHex } = await computeSHA256(uint8Data);
  state.encryptFile.hashHex = hashHex;
  $('dna-encrypt-hash').textContent = hashHex;

  // Blocks & Padding calculation
  const blockCount = Math.floor(uint8Data.length / 8) + 1;
  const paddingBytes = 8 - (uint8Data.length % 8);
  $('dna-encrypt-blocks').textContent = `${blockCount.toLocaleString()} DES Blocks · ${paddingBytes} PKCS#7 pad bytes`;

  // Shannon Entropy calculation
  const { entropy, interpretation } = calculateEntropy(uint8Data);
  state.encryptFile.entropy = entropy;
  $('dna-encrypt-entropy').textContent = `${entropy} / 8.000 bits/byte`;
  $('dna-entropy-fill').style.width = `${Math.min(100, (entropy / 8.0) * 100)}%`;
  $('dna-entropy-tag').textContent = interpretation;

  // File Preview
  renderFilePreview(state.encryptFile, $('encrypt-preview-box'), $('encrypt-preview-content'));

  // Pre-generate secure key if field is empty
  if (!$('input-encrypt-key').value) {
    generateAndSetEncryptKey();
  }
}

function clearEncryptFile() {
  state.encryptFile = null;
  state.encryptedResult = null;
  $('input-encrypt-file').value = '';
  $('encrypt-dropzone').style.display = 'flex';
  $('card-encrypt-file-selected').style.display = 'none';
  $('card-encrypt-dna').style.display = 'none';
  $('encrypt-success-box').style.display = 'none';
  $('encrypt-journey-box').classList.remove('active');
  hideNotification('encrypt');
}

function renderFilePreview(fileObj, containerBox, contentEl) {
  contentEl.innerHTML = '';
  const type = fileObj.type;
  const data = fileObj.data;

  // Image preview
  if (type.startsWith('image/')) {
    const blob = new Blob([data], { type });
    const url = URL.createObjectURL(blob);
    const img = document.createElement('img');
    img.className = 'preview-image';
    img.src = url;
    contentEl.appendChild(img);
    containerBox.style.display = 'block';
    return;
  }

  // Text / Code preview
  if (
    type.startsWith('text/') ||
    type === 'application/json' ||
    type === 'application/javascript' ||
    type === 'application/xml' ||
    fileObj.name.match(/\.(txt|md|json|js|mjs|ts|html|css|py|java|c|cpp|sql|sh|xml)$/i)
  ) {
    try {
      const textDecoder = new TextDecoder('utf-8', { fatal: false });
      const snippet = textDecoder.decode(data.subarray(0, 2048));
      const pre = document.createElement('pre');
      pre.className = 'preview-code';
      pre.textContent = snippet + (data.length > 2048 ? '\n... [Remaining content truncated for preview]' : '');
      contentEl.appendChild(pre);
      containerBox.style.display = 'block';
      return;
    } catch {}
  }

  // Audio / Video preview
  if (type.startsWith('audio/')) {
    const blob = new Blob([data], { type });
    const audio = document.createElement('audio');
    audio.controls = true;
    audio.src = URL.createObjectURL(blob);
    audio.style.width = '100%';
    contentEl.appendChild(audio);
    containerBox.style.display = 'block';
    return;
  }

  containerBox.style.display = 'none';
}

function setupEncryptHandlers() {
  const dropzone = $('encrypt-dropzone');
  const fileInput = $('input-encrypt-file');

  dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('drag-active'); });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag-active'));
  dropzone.addEventListener('drop', async (e) => {
    e.preventDefault();
    dropzone.classList.remove('drag-active');
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      const buffer = await file.arrayBuffer();
      await loadFileForEncryption(file, new Uint8Array(buffer));
    }
  });

  $('btn-browse-encrypt').addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', async () => {
    if (fileInput.files && fileInput.files[0]) {
      const file = fileInput.files[0];
      const buffer = await file.arrayBuffer();
      await loadFileForEncryption(file, new Uint8Array(buffer));
    }
  });

  $('btn-remove-encrypt-file').addEventListener('click', clearEncryptFile);

  // Key format tabs
  const tabAscii = $('key-tab-ascii');
  const tabHex = $('key-tab-hex');
  const tabPass = $('key-tab-pass');
  const keyInput = $('input-encrypt-key');

  const setKeyFormat = (fmt) => {
    state.encryptKeyFormat = fmt;
    [tabAscii, tabHex, tabPass].forEach(t => t.classList.remove('active'));
    if (fmt === 'ascii') {
      tabAscii.classList.add('active');
      keyInput.placeholder = 'Enter 8-character ASCII key (e.g. MyKey123)';
      keyInput.maxLength = 8;
    } else if (fmt === 'hex') {
      tabHex.classList.add('active');
      keyInput.placeholder = 'Enter 16 hexadecimal digits (e.g. 133457799BBCDFF1)';
      keyInput.maxLength = 16;
    } else {
      tabPass.classList.add('active');
      keyInput.placeholder = 'Enter passphrase to derive 64-bit DES key via PBKDF2';
      keyInput.maxLength = 64;
    }
  };

  tabAscii.addEventListener('click', () => setKeyFormat('ascii'));
  tabHex.addEventListener('click', () => setKeyFormat('hex'));
  tabPass.addEventListener('click', () => setKeyFormat('passphrase'));

  // Key Generation
  $('btn-gen-encrypt-key').addEventListener('click', generateAndSetEncryptKey);

  // Show / Hide Key
  $('btn-toggle-key-visibility').addEventListener('click', () => {
    const isPass = keyInput.type === 'password';
    keyInput.type = isPass ? 'text' : 'password';
    $('btn-toggle-key-visibility').textContent = isPass ? 'Hide Key' : 'Show Key';
  });

  // Copy Key
  $('btn-copy-encrypt-key').addEventListener('click', async () => {
    const val = keyInput.value;
    if (!val) return;
    try {
      await navigator.clipboard.writeText(val);
      showNotification('encrypt', 'DES Key copied to clipboard.', 'success');
    } catch {
      showNotification('encrypt', 'Clipboard copy unavailable.', 'error');
    }
  });

  // Download Keyfile (.deskey)
  $('btn-export-keyfile').addEventListener('click', exportCurrentKeyfile);

  // Show Key as QR
  $('btn-qr-key').addEventListener('click', () => {
    const keyVal = keyInput.value.trim();
    if (!keyVal) {
      showNotification('encrypt', 'Please enter or generate a key first.', 'error');
      return;
    }
    openQRModal(keyVal);
  });

  // Mode Selection (CBC vs ECB)
  const cardCbc = $('mode-card-cbc');
  const cardEcb = $('mode-card-ecb');

  cardCbc.addEventListener('click', () => {
    state.encryptMode = MODE_CBC;
    cardCbc.classList.add('selected');
    cardEcb.classList.remove('selected');
  });

  cardEcb.addEventListener('click', () => {
    state.encryptMode = MODE_ECB;
    cardEcb.classList.add('selected');
    cardCbc.classList.remove('selected');
  });

  // Main Encrypt Trigger
  $('btn-run-encrypt').addEventListener('click', executeEncryption);

  // Success actions
  $('btn-download-dvlt').addEventListener('click', downloadEncryptedVaultFile);
  $('btn-download-success-key').addEventListener('click', exportCurrentKeyfile);
  $('btn-view-in-lab').addEventListener('click', () => {
    if (state.encryptFile && state.encryptFile.data) {
      // Load first 8 bytes into lab
      const first8 = state.encryptFile.data.subarray(0, 8);
      const pad8 = new Uint8Array(8);
      pad8.set(first8);
      $('lab-input-block').value = bytesToHex(pad8);
      $('lab-input-key').value = bytesToHex(state.encryptedResult?.keyBytes || new Uint8Array(8));
      switchView('lab');
      runFeistelSimulation();
    }
  });
  $('btn-encrypt-another').addEventListener('click', clearEncryptFile);
}

function generateAndSetEncryptKey() {
  const gen = generateRandomKey();
  const keyInput = $('input-encrypt-key');
  if (state.encryptKeyFormat === 'hex') {
    keyInput.value = gen.hex;
  } else if (state.encryptKeyFormat === 'ascii') {
    keyInput.value = gen.asciiStr;
  } else {
    keyInput.value = gen.asciiStr;
  }
  state.currentKeyText = keyInput.value;
}

function exportCurrentKeyfile() {
  const keyVal = $('input-encrypt-key').value.trim();
  if (!keyVal) {
    showNotification('encrypt', 'Please enter or generate a key before exporting.', 'error');
    return;
  }

  let keyBytes;
  try {
    if (state.encryptKeyFormat === 'hex') keyBytes = parseDesKey(keyVal, 'hex');
    else if (state.encryptKeyFormat === 'ascii') keyBytes = parseDesKey(keyVal, 'ascii');
    else keyBytes = parseDesKey(keyVal.slice(0, 8).padEnd(8, 'X'), 'ascii');
  } catch (err) {
    showNotification('encrypt', err.message, 'error');
    return;
  }

  const filename = state.encryptFile ? state.encryptFile.name : 'des_key';
  const content = generateKeyfileContent({
    keyBytes,
    originalFilename: filename
  });

  downloadTextBlob(content, `${filename}.deskey`);
}

async function executeEncryption() {
  if (state.encryptContentType === 'text') {
    return executeTextEncryption();
  }

  if (!state.encryptFile) {
    showNotification('encrypt', 'Please select or drop a file to encrypt first.', 'error');
    return;
  }

  const keyText = $('input-encrypt-key').value.trim();
  if (!keyText) {
    showNotification('encrypt', 'Please enter or generate an 8-byte DES key.', 'error');
    return;
  }

  let keyBytes;
  try {
    if (state.encryptKeyFormat === 'passphrase') {
      keyBytes = await deriveKeyFromPassphrase(keyText);
    } else {
      keyBytes = parseDesKey(keyText, state.encryptKeyFormat);
    }
  } catch (err) {
    showNotification('encrypt', err.message, 'error');
    return;
  }

  hideNotification('encrypt');
  const journeyBox = $('encrypt-journey-box');
  journeyBox.classList.add('active');

  const setStep = (num) => {
    for (let i = 1; i <= 7; i++) {
      const el = $(`j-step-${i}`);
      if (el) {
        if (i < num) el.className = 'journey-step-item completed';
        else if (i === num) el.className = 'journey-step-item active';
        else el.className = 'journey-step-item';
      }
    }
  };

  const progressFill = $('encrypt-progress-fill');
  const progressText = $('encrypt-progress-text');
  const progressPct = $('encrypt-progress-pct');

  const onProgress = (pct) => {
    progressFill.style.width = `${pct}%`;
    progressPct.textContent = `${pct}%`;
    progressText.textContent = `Running 16 Feistel rounds (${pct}%)...`;
  };

  const btnEncrypt = $('btn-run-encrypt');
  btnEncrypt.disabled = true;

  try {
    setStep(1);
    await new Promise(r => setTimeout(r, 60));

    setStep(2);
    await new Promise(r => setTimeout(r, 60));

    setStep(3);
    await new Promise(r => setTimeout(r, 60));

    setStep(4);
    await new Promise(r => setTimeout(r, 60));

    setStep(5);
    const t0 = performance.now();
    const result = await createVaultContainer({
      fileData: state.encryptFile.data,
      keyBytes,
      filename: state.encryptFile.name,
      mimeType: state.encryptFile.type,
      mode: state.encryptMode,
      onProgress
    });
    const elapsed = Math.round(performance.now() - t0);

    setStep(6);
    await new Promise(r => setTimeout(r, 80));

    setStep(7);
    state.encryptedResult = {
      ...result,
      keyBytes,
      keyHex: bytesToHex(keyBytes),
      elapsed
    };

    // Render Success Card
    $('success-orig-name').textContent = state.encryptFile.name;
    $('success-orig-meta').textContent = `${formatBytes(state.encryptFile.size)} · ${state.encryptFile.type}`;
    $('success-orig-hash').textContent = `SHA-256: ${result.originalHashHex}`;
    $('success-enc-name').textContent = `${state.encryptFile.name}.dvlt`;
    $('success-enc-meta').textContent = `${formatBytes(result.encryptedSize)} · DES Vault Container`;
    $('success-mode-tag').textContent = `DES-${state.encryptMode} · 16 Rounds (${elapsed}ms)`;

    $('encrypt-success-box').style.display = 'block';

    // Log to safe history
    addHistoryEntry({
      operation: 'ENCRYPT',
      filename: state.encryptFile.name,
      fileSize: state.encryptFile.size,
      mode: state.encryptMode,
      hashHex: result.originalHashHex,
      status: 'SUCCESS'
    });
    updateDashboardStats();

  } catch (err) {
    showNotification('encrypt', `Encryption failed: ${err.message}`, 'error');
    addHistoryEntry({
      operation: 'ENCRYPT',
      filename: state.encryptFile.name,
      fileSize: state.encryptFile.size,
      mode: state.encryptMode,
      status: 'FAILED',
      errorReason: err.message
    });
  } finally {
    btnEncrypt.disabled = false;
  }
}

function downloadEncryptedVaultFile() {
  if (!state.encryptedResult) return;
  const blob = new Blob([state.encryptedResult.containerBytes], { type: 'application/octet-stream' });
  const filename = `${state.encryptFile.name}.dvlt`;
  downloadBlob(blob, filename);
}

// ==========================================
// DECRYPT WORKFLOW
// ==========================================
async function loadFileForDecryption(file, uint8Data) {
  state.decryptFile = {
    file,
    data: uint8Data,
    name: sanitizeFilename(file.name)
  };

  hideNotification('decrypt');
  $('decrypt-success-box').style.display = 'none';

  try {
    const inspection = inspectVaultContainer(uint8Data);
    state.decryptFile.inspection = inspection;

    $('decrypt-dropzone').style.display = 'none';
    $('card-decrypt-container-info').style.display = 'block';

    $('dec-meta-name').textContent = `${inspection.metadata.filename} (${inspection.metadata.mimeType || 'binary'})`;
    $('dec-meta-algo').textContent = `${inspection.algorithm} · ${inspection.mode} Mode`;
    $('dec-meta-hash').textContent = inspection.originalHashHex;
    $('dec-meta-iv').textContent = `Size: ${formatBytes(uint8Data.length)} · IV: ${inspection.ivHex}`;

  } catch (err) {
    showNotification('decrypt', `Invalid container: ${err.message}`, 'error');
    $('card-decrypt-container-info').style.display = 'none';
    $('decrypt-dropzone').style.display = 'flex';
    state.decryptFile = null;
  }
}

function setupDecryptHandlers() {
  const dropzone = $('decrypt-dropzone');
  const fileInput = $('input-decrypt-file');

  dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('drag-active'); });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag-active'));
  dropzone.addEventListener('drop', async (e) => {
    e.preventDefault();
    dropzone.classList.remove('drag-active');
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      const buffer = await file.arrayBuffer();
      await loadFileForDecryption(file, new Uint8Array(buffer));
    }
  });

  $('btn-browse-decrypt').addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', async () => {
    if (fileInput.files && fileInput.files[0]) {
      const file = fileInput.files[0];
      const buffer = await file.arrayBuffer();
      await loadFileForDecryption(file, new Uint8Array(buffer));
    }
  });

  // Key toggle
  $('btn-toggle-decrypt-key').addEventListener('click', () => {
    const input = $('input-decrypt-key');
    const isPass = input.type === 'password';
    input.type = isPass ? 'text' : 'password';
    $('btn-toggle-decrypt-key').textContent = isPass ? 'Hide Key' : 'Show Key';
  });

  // Load Keyfile (.deskey)
  $('btn-load-keyfile').addEventListener('click', () => $('input-keyfile-upload').click());
  $('input-keyfile-upload').addEventListener('change', async () => {
    const input = $('input-keyfile-upload');
    if (input.files && input.files[0]) {
      const text = await input.files[0].text();
      try {
        const hex = parseKeyfileContent(text);
        $('input-decrypt-key').value = hex;
        showNotification('decrypt', 'DES Key successfully imported from keyfile.', 'success');
      } catch (err) {
        showNotification('decrypt', err.message, 'error');
      }
    }
  });

  // Main Decrypt Trigger
  $('btn-run-decrypt').addEventListener('click', executeDecryption);

  // Success actions
  $('btn-download-restored').addEventListener('click', () => {
    if (!state.decryptedResult) return;
    const blob = new Blob([state.decryptedResult.restoredData], {
      type: state.decryptedResult.mimeType || 'application/octet-stream'
    });
    downloadBlob(blob, state.decryptedResult.filename);
  });

  $('btn-decrypt-another').addEventListener('click', () => {
    state.decryptFile = null;
    state.decryptedResult = null;
    $('input-decrypt-file').value = '';
    $('decrypt-dropzone').style.display = 'flex';
    $('card-decrypt-container-info').style.display = 'none';
    $('decrypt-success-box').style.display = 'none';
    $('decrypt-journey-box').classList.remove('active');
    hideNotification('decrypt');
  });
}

async function executeDecryption() {
  if (state.decryptContentType === 'text') {
    return executeTextDecryption();
  }

  if (!state.decryptFile) {
    showNotification('decrypt', 'Please select or drop a valid .dvlt file first.', 'error');
    return;
  }

  const keyText = $('input-decrypt-key').value.trim();
  if (!keyText) {
    showNotification('decrypt', 'Please enter your matching DES key.', 'error');
    return;
  }

  let keyBytes;
  try {
    // Auto detect hex vs ascii
    if (/^[0-9a-fA-F]{16}$/.test(keyText)) {
      keyBytes = parseDesKey(keyText, 'hex');
    } else {
      keyBytes = parseDesKey(keyText, 'ascii');
    }
  } catch (err) {
    showNotification('decrypt', err.message, 'error');
    return;
  }

  hideNotification('decrypt');
  const journeyBox = $('decrypt-journey-box');
  journeyBox.classList.add('active');

  const progressFill = $('decrypt-progress-fill');
  const progressText = $('decrypt-progress-text');
  const progressPct = $('decrypt-progress-pct');

  const onProgress = (pct) => {
    progressFill.style.width = `${pct}%`;
    progressPct.textContent = `${pct}%`;
    progressText.textContent = `Decrypting 64-bit blocks (${pct}%)...`;
  };

  const btnDecrypt = $('btn-run-decrypt');
  btnDecrypt.disabled = true;

  try {
    const result = await openVaultContainer(state.decryptFile.data, keyBytes, onProgress);
    state.decryptedResult = result;

    // Render Success Card
    $('dec-success-source-name').textContent = state.decryptFile.name;
    $('dec-success-source-meta').textContent = `${formatBytes(state.decryptFile.data.length)} · DVLT Container`;
    $('dec-success-orig-name').textContent = result.filename;
    $('dec-success-orig-meta').textContent = `${formatBytes(result.originalSize)} · Restored ${result.mimeType || 'Binary'}`;

    // Render Preview of restored content
    renderFilePreview(
      {
        type: result.mimeType || 'application/octet-stream',
        data: result.restoredData,
        name: result.filename
      },
      $('decrypt-preview-box'),
      $('decrypt-preview-content')
    );

    $('decrypt-success-box').style.display = 'block';

    addHistoryEntry({
      operation: 'DECRYPT',
      filename: result.filename,
      fileSize: result.originalSize,
      mode: result.mode,
      hashHex: result.hashHex,
      status: 'SUCCESS'
    });
    updateDashboardStats();

  } catch (err) {
    showNotification('decrypt', err.message, 'error');
    $('decrypt-success-box').style.display = 'none';

    addHistoryEntry({
      operation: 'DECRYPT',
      filename: state.decryptFile?.inspection?.metadata?.filename || state.decryptFile.name,
      fileSize: 0,
      mode: state.decryptFile?.inspection?.mode || 'CBC',
      status: 'FAILED',
      errorReason: err.message
    });
  } finally {
    btnDecrypt.disabled = false;
  }
}

// ==========================================
// DES LAB (INTERACTIVE WORKBENCH)
// ==========================================
function setupLabHandlers() {
  $('btn-run-feistel-sim').addEventListener('click', runFeistelSimulation);
  $('btn-run-ecb-cbc-exp').addEventListener('click', runEcbCbcExperiment);
}

function runDefaultLabSim() {
  runFeistelSimulation();
  runKeyScheduleSim();
  runEcbCbcExperiment();
}

function runFeistelSimulation() {
  const plainInput = $('lab-input-block').value.trim();
  const keyInput = $('lab-input-key').value.trim();

  let blockBytes, keyBytes;
  try {
    if (/^[0-9a-fA-F]{16}$/.test(plainInput)) blockBytes = hexToBytes(plainInput);
    else blockBytes = parseDesKey(plainInput.padEnd(8, ' '), 'ascii');

    if (/^[0-9a-fA-F]{16}$/.test(keyInput)) keyBytes = hexToBytes(keyInput);
    else keyBytes = parseDesKey(keyInput.padEnd(8, ' '), 'ascii');
  } catch (err) {
    alert('Lab Input Error: ' + err.message);
    return;
  }

  const trace = traceBlockEncryption(blockBytes, keyBytes);

  $('lab-node-plain').textContent = `${trace.plaintextHex} (Bits: ${trace.rawBits.slice(0, 16)}...)`;
  $('lab-node-ip').textContent = `L₀: ${trace.l0Hex} · R₀: ${trace.r0Hex}`;
  $('lab-node-prefp').textContent = `Pre-FP (R₁₆ | L₁₆): ${trace.preFpHex}`;
  $('lab-node-cipher').textContent = `${trace.ciphertextHex} (Bits: ${trace.fpBits.slice(0, 16)}...)`;

  // Render 16 rounds
  const roundsContainer = $('lab-rounds-list');
  roundsContainer.innerHTML = '';

  trace.rounds.forEach(r => {
    const item = document.createElement('div');
    item.className = 'round-item' + (r.roundNumber === 1 ? ' expanded' : '');

    let sboxesHtml = '';
    r.sboxDetails.forEach(s => {
      sboxesHtml += `<tr>
        <td><strong>S${s.sboxNumber}</strong></td>
        <td><code>${s.input6Bits}</code></td>
        <td>Row ${s.row}</td>
        <td>Col ${s.col}</td>
        <td><code>${s.output4Bits}</code> (${s.outputDec})</td>
      </tr>`;
    });

    item.innerHTML = `
      <div class="round-header-row">
        <span class="round-title-pill">
          <span>Round ${String(r.roundNumber).padStart(2, '0')}</span>
          <span style="font-size: 0.75rem; color: var(--cyan-bright); font-family: var(--font-mono);">Subkey K${r.roundNumber}</span>
        </span>
        <div class="round-mini-vals">
          <span>L: <code>${r.newLHex}</code></span>
          <span>R: <code>${r.newRHex}</code></span>
        </div>
      </div>
      <div class="round-details-body">
        <div style="font-size: 0.75rem; color: var(--text-muted); line-height: 1.6; margin-bottom: 8px;">
          <div>• Expansion E(R<sub>${r.roundNumber-1}</sub>): <code>${r.expandedBits.slice(0, 24)}...</code> (48 bits)</div>
          <div>• Subkey K<sub>${r.roundNumber}</sub>: <code>${r.keyBits.slice(0, 24)}...</code> (48 bits)</div>
          <div>• E(R) ⊕ K: <code>${r.xorBits.slice(0, 24)}...</code> (48 bits)</div>
          <div>• P-Permutation: <code>${r.pOutputHex}</code> (32 bits)</div>
          <div>• Feistel XOR: L<sub>${r.roundNumber-1}</sub> ⊕ P(S) → R<sub>${r.roundNumber}</sub> (<code>${r.newRHex}</code>)</div>
        </div>
        <div style="font-weight: 700; color: #fff; font-size: 0.75rem; margin-top: 8px;">8 S-Box Substitutions:</div>
        <table class="sbox-table">
          <thead>
            <tr><th>S-Box</th><th>6-Bit Input</th><th>Row</th><th>Col</th><th>4-Bit Output</th></tr>
          </thead>
          <tbody>
            ${sboxesHtml}
          </tbody>
        </table>
      </div>
    `;

    item.querySelector('.round-header-row').addEventListener('click', () => {
      item.classList.toggle('expanded');
    });

    roundsContainer.appendChild(item);
  });
}

function runKeyScheduleSim() {
  const keyInput = $('lab-input-key').value.trim();
  let keyBytes;
  try {
    if (/^[0-9a-fA-F]{16}$/.test(keyInput)) keyBytes = hexToBytes(keyInput);
    else keyBytes = parseDesKey(keyInput.padEnd(8, ' '), 'ascii');
  } catch {
    keyBytes = hexToBytes('133457799BBCDFF1');
  }

  const trace = generateKeyScheduleTrace(keyBytes);
  const container = $('lab-keyschedule-container');

  let rows = '';
  trace.rounds.forEach(r => {
    rows += `<tr>
      <td><strong>K${r.roundNumber}</strong></td>
      <td>${r.shift}</td>
      <td><code>${r.cBits.slice(0, 14)}...</code></td>
      <td><code>${r.dBits.slice(0, 14)}...</code></td>
      <td><strong style="color: var(--cyan-bright); font-family: var(--font-mono);">${r.kHex}</strong></td>
    </tr>`;
  });

  container.innerHTML = `
    <table class="sbox-table">
      <thead>
        <tr><th>Round</th><th>Shift Bits</th><th>C Register (28b)</th><th>D Register (28b)</th><th>48-Bit Subkey (Hex)</th></tr>
      </thead>
      <tbody>
        ${rows}
      </tbody>
    </table>
  `;
}

async function runEcbCbcExperiment() {
  const key = hexToBytes('133457799BBCDFF1');
  // Two identical 8-byte blocks: "ATTACKAT" and "ATTACKAT" (16 bytes total)
  const plain = new TextEncoder().encode('ATTACKATATTACKAT');
  const iv = hexToBytes('0123456789ABCDEF');

  const cipherECB = await encryptECB(plain, key);
  const cipherCBC = await encryptCBC(plain, key, iv);

  const block1ECB = bytesToHex(cipherECB.subarray(0, 8));
  const block2ECB = bytesToHex(cipherECB.subarray(8, 16));

  const block1CBC = bytesToHex(cipherCBC.subarray(0, 8));
  const block2CBC = bytesToHex(cipherCBC.subarray(8, 16));

  const container = $('ecb-cbc-results-box');
  container.innerHTML = `
    <div class="exp-column">
      <div class="exp-col-title">DES-ECB Mode</div>
      <span class="exp-col-badge badge-leak">⚠️ Pattern Leakage</span>
      <p style="font-size: 0.8125rem; color: var(--text-dim); margin-bottom: 10px;">
        Both identical 8-byte plaintext blocks produce <strong>EXACTLY IDENTICAL</strong> ciphertext:
      </p>
      <div class="exp-code-block">Block 1: ${block1ECB}</div>
      <div class="exp-code-block">Block 2: ${block2ECB}</div>
      <div style="font-size: 0.75rem; color: #f87171; font-weight: 600; margin-top: 6px;">
        Block 1 === Block 2: TRUE (Exposes patterns in structured documents & images)
      </div>
    </div>
    <div class="exp-column">
      <div class="exp-col-title">DES-CBC Mode</div>
      <span class="exp-col-badge badge-secure">✓ Cryptographic Diffusion</span>
      <p style="font-size: 0.8125rem; color: var(--text-dim); margin-bottom: 10px;">
        Because Block 2 is XORed with Ciphertext 1 before encryption, ciphertexts are <strong>COMPLETELY DIFFERENT</strong>:
      </p>
      <div class="exp-code-block">Block 1: ${block1CBC}</div>
      <div class="exp-code-block">Block 2: ${block2CBC}</div>
      <div style="font-size: 0.75rem; color: #34d399; font-weight: 600; margin-top: 6px;">
        Block 1 !== Block 2: TRUE (Patterns are eliminated by block chaining)
      </div>
    </div>
  `;
}

// ==========================================
// FILE INSPECTOR
// ==========================================
function setupInspectorHandlers() {
  const dropzone = $('inspector-dropzone');
  const fileInput = $('input-inspector-file');

  dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('drag-active'); });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag-active'));
  dropzone.addEventListener('drop', async (e) => {
    e.preventDefault();
    dropzone.classList.remove('drag-active');
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      await inspectFile(e.dataTransfer.files[0]);
    }
  });

  $('btn-browse-inspector').addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', async () => {
    if (fileInput.files && fileInput.files[0]) {
      await inspectFile(fileInput.files[0]);
    }
  });
}

async function inspectFile(file) {
  const buffer = await file.arrayBuffer();
  const data = new Uint8Array(buffer);
  const container = $('inspector-results');
  container.style.display = 'block';

  const { hex: hashHex } = await computeSHA256(data);
  const { entropy, interpretation, frequencies } = calculateEntropy(data);

  const blockCount = Math.floor(data.length / 8) + 1;
  const padBytes = 8 - (data.length % 8);

  // Generate Hex Dump of first 256 bytes
  const hexDumpBytes = data.subarray(0, 256);
  let hexDumpHtml = '';
  for (let i = 0; i < hexDumpBytes.length; i += 16) {
    const chunk = hexDumpBytes.subarray(i, i + 16);
    const offset = i.toString(16).padStart(4, '0').toUpperCase();
    const hexPart = Array.from(chunk).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ').padEnd(48, ' ');
    const asciiPart = Array.from(chunk).map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.').join('');
    hexDumpHtml += `${offset}:  ${hexPart}  |${asciiPart}|\n`;
  }

  container.innerHTML = `
    <div class="file-dna-card" style="margin-top: 0;">
      <div class="file-dna-head">
        <span class="file-dna-title">File Telemetry & Cryptographic DNA</span>
        <span style="font-size: 0.75rem; color: var(--text-dim);">${file.name}</span>
      </div>
      <div class="file-dna-grid">
        <div class="dna-data-box">
          <div class="dna-box-label">File Size</div>
          <div class="dna-box-val">${formatBytes(data.length)} (${data.length.toLocaleString()} bytes)</div>
        </div>
        <div class="dna-data-box">
          <div class="dna-box-label">MIME Type / Format</div>
          <div class="dna-box-val">${file.type || 'application/octet-stream'}</div>
        </div>
        <div class="dna-data-box">
          <div class="dna-box-label">SHA-256 Checksum Fingerprint</div>
          <div class="dna-box-val" style="font-size: 0.75rem;">${hashHex}</div>
        </div>
        <div class="dna-data-box">
          <div class="dna-box-label">DES Blocks & PKCS#7 Padding</div>
          <div class="dna-box-val">${blockCount.toLocaleString()} Blocks · ${padBytes} pad bytes</div>
        </div>
        <div class="dna-data-box" style="grid-column: 1 / -1;">
          <div class="dna-box-label">Shannon Entropy (0..8)</div>
          <div class="dna-box-val">${entropy} bits/byte</div>
          <div class="entropy-meter-wrap">
            <div class="entropy-bar-track">
              <div class="entropy-bar-fill" style="width: ${Math.min(100, (entropy / 8.0) * 100)}%;"></div>
            </div>
            <div class="entropy-tagline">${interpretation}</div>
          </div>
        </div>
      </div>

      <div style="margin-top: 20px;">
        <div class="file-preview-title">First 256 Bytes Binary Hex Dump (Offset | Hex | ASCII)</div>
        <pre class="preview-code" style="max-height: 240px; overflow: auto;">${hexDumpHtml}</pre>
      </div>
    </div>
  `;
}

// ==========================================
// HISTORY MANAGEMENT
// ==========================================
function renderHistoryTable() {
  const history = getHistory();
  const tbody = $('history-tbody');
  const countBadge = $('history-count-badge');
  countBadge.textContent = `${history.length} Operations Logged`;

  if (history.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-dim); padding: 32px;">No cryptographic operations recorded yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = history.map(item => `
    <tr>
      <td>
        <span class="op-badge ${item.operation.toLowerCase()}">${item.operation}</span>
      </td>
      <td><strong style="color: #fff;">${item.filename}</strong></td>
      <td>${formatBytes(item.fileSize)}</td>
      <td>DES-${item.mode || 'CBC'}</td>
      <td><code style="font-size: 0.75rem;">${item.hashPrefix}</code></td>
      <td>
        <span style="color: ${item.status === 'SUCCESS' ? 'var(--emerald-success)' : 'var(--rose-danger)'}; font-weight: 600;">
          ${item.status === 'SUCCESS' ? '✓ Success' : '✕ Failed'}
        </span>
      </td>
      <td>${timeAgo(item.timestamp)}</td>
    </tr>
  `).join('');
}

function setupHistoryHandlers() {
  $('btn-clear-history').addEventListener('click', () => {
    if (confirm('Are you sure you want to clear your operation history?')) {
      clearHistory();
      renderHistoryTable();
      updateDashboardStats();
    }
  });

  $('btn-export-history').addEventListener('click', () => {
    const history = getHistory();
    downloadTextBlob(JSON.stringify(history, null, 2), 'des_vault_history.json');
  });
}

// ==========================================
// MODALS (QR, TESTS, DEMO TOUR)
// ==========================================
function openQRModal(keyText) {
  const modal = $('modal-qr');
  const container = $('modal-qr-container');
  const textEl = $('modal-qr-key-text');

  container.innerHTML = generateKeyQRCodeSVG(keyText, 220);
  textEl.textContent = `KEY: ${keyText}`;
  modal.classList.add('active');
}

function setupModalHandlers() {
  // QR modal
  $('btn-close-qr-modal').addEventListener('click', () => $('modal-qr').classList.remove('active'));

  // Test suite modal
  $('btn-header-test').addEventListener('click', () => {
    $('modal-tests').classList.add('active');
    triggerTestSuiteRun();
  });
  $('btn-close-test-modal').addEventListener('click', () => $('modal-tests').classList.remove('active'));
  $('btn-trigger-tests-run').addEventListener('click', triggerTestSuiteRun);

  // Demo Tour modal
  $('btn-header-demo').addEventListener('click', () => {
    $('modal-demo').classList.add('active');
    setupDemoTourSteps();
  });
  $('btn-close-demo-modal').addEventListener('click', () => $('modal-demo').classList.remove('active'));
}

async function triggerTestSuiteRun() {
  const list = $('modal-test-results-list');
  list.innerHTML = '<div style="color: var(--cyan-bright); padding: 12px; font-family: var(--font-mono);">Executing FIPS 46-3 test suite...</div>';

  const results = await runAllTests();
  list.innerHTML = results.map(r => `
    <div class="test-item-row">
      <span>${r.name}</span>
      <span class="${r.passed ? 'test-pass' : 'test-fail'}">
        ${r.passed ? `✓ PASS (${r.durationMs}ms)` : `✕ FAIL (${r.details})`}
      </span>
    </div>
  `).join('');
}

// Guided Demo Tour Logic
function setupDemoTourSteps() {
  let demoKeyHex = '133457799BBCDFF1';
  let demoPdfBytes = SAMPLE_FILES[1].getData();
  let demoDvltBytes = null;
  const feedback = $('demo-tour-feedback');

  $('demo-step-1').onclick = async () => {
    await loadFileForEncryption({
      name: 'fips46_whitepaper.pdf',
      type: 'application/pdf',
      size: demoPdfBytes.length,
      lastModified: Date.now()
    }, demoPdfBytes);
    switchView('encrypt');
    $('modal-demo').classList.remove('active');
  };

  $('demo-step-2').onclick = () => {
    $('input-encrypt-key').value = demoKeyHex;
    state.encryptKeyFormat = 'hex';
    $('key-tab-hex').click();
    feedback.textContent = `Key set: ${demoKeyHex} (64 bits, 56 effective). Ready to encrypt.`;
  };

  $('demo-step-3').onclick = async () => {
    $('modal-demo').classList.remove('active');
    switchView('encrypt');
    await executeEncryption();
  };

  $('demo-step-4').onclick = async () => {
    feedback.textContent = 'Testing wrong key rejection on .dvlt file...';
    try {
      if (!state.encryptedResult) {
        feedback.textContent = 'Please run Step 3 (Encrypt) first!';
        return;
      }
      await openVaultContainer(state.encryptedResult.containerBytes, parseDesKey('wrongkey', 'ascii'));
      feedback.textContent = 'Error: Wrong key was accepted!';
    } catch (err) {
      feedback.textContent = `✓ Proved: Wrong key was safely rejected: "${err.message.slice(0, 70)}..."`;
    }
  };

  $('demo-step-5').onclick = async () => {
    if (!state.encryptedResult) {
      feedback.textContent = 'Please run Step 3 (Encrypt) first!';
      return;
    }
    await loadFileForDecryption({
      name: `${state.encryptFile.name}.dvlt`,
      type: 'application/octet-stream',
      size: state.encryptedResult.containerBytes.length
    }, state.encryptedResult.containerBytes);
    $('input-decrypt-key').value = demoKeyHex;
    switchView('decrypt');
    $('modal-demo').classList.remove('active');
    await executeDecryption();
  };
}

// ==========================================
// TOAST NOTIFICATIONS & BLOB DOWNLOADS
// ==========================================
function showNotification(type, message, level = 'error') {
  const banner = $(`${type}-notification`);
  if (!banner) return;
  banner.textContent = message;
  banner.className = `notification-banner active ${level}`;
}

function hideNotification(type) {
  const banner = $(`${type}-notification`);
  if (banner) banner.className = 'notification-banner';
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = sanitizeFilename(filename);
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function downloadTextBlob(text, filename) {
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  downloadBlob(blob, filename);
}

// ==========================================
// TEXT NOTE MODE HANDLERS & EXECUTORS
// ==========================================
function setupTextModeHandlers() {
  const toggleEncFile = $('toggle-encrypt-file');
  const toggleEncText = $('toggle-encrypt-text');
  const panelEncFile = $('panel-encrypt-file');
  const panelEncText = $('panel-encrypt-text');
  const btnRunEncrypt = $('btn-run-encrypt');

  toggleEncFile.addEventListener('click', () => {
    state.encryptContentType = 'file';
    toggleEncFile.classList.add('active');
    toggleEncText.classList.remove('active');
    panelEncFile.style.display = 'block';
    panelEncText.style.display = 'none';
    $('text-encrypt-success-box').style.display = 'none';
    btnRunEncrypt.querySelector('span').textContent = 'Encrypt & Build .dvlt Container';
  });

  toggleEncText.addEventListener('click', () => {
    state.encryptContentType = 'text';
    toggleEncText.classList.add('active');
    toggleEncFile.classList.remove('active');
    panelEncText.style.display = 'block';
    panelEncFile.style.display = 'none';
    $('encrypt-success-box').style.display = 'none';
    btnRunEncrypt.querySelector('span').textContent = 'Encrypt Text Note';
  });

  // Text telemetry on typing
  const inputEncText = $('input-encrypt-text');
  inputEncText.addEventListener('input', () => {
    const text = inputEncText.value;
    const chars = text.length;
    const bytes = new TextEncoder().encode(text).length;
    const blocks = bytes === 0 ? 1 : Math.floor(bytes / 8) + 1;
    const padding = 8 - (bytes % 8);

    $('text-chars-count').textContent = `${chars.toLocaleString()} Chars`;
    $('text-bytes-count').textContent = `${bytes.toLocaleString()} Bytes (UTF-8)`;
    $('text-blocks-count').textContent = `${blocks.toLocaleString()} DES Blocks`;
    $('text-padding-count').textContent = `${padding} PKCS#7 Pad Bytes`;
  });

  // Format selection
  const btnFmtB64 = $('btn-format-b64');
  const btnFmtHex = $('btn-format-hex');
  btnFmtB64.addEventListener('click', () => {
    state.textOutputFormat = 'base64';
    btnFmtB64.classList.add('active');
    btnFmtHex.classList.remove('active');
  });
  btnFmtHex.addEventListener('click', () => {
    state.textOutputFormat = 'hex';
    btnFmtHex.classList.add('active');
    btnFmtB64.classList.remove('active');
  });

  // Text result buttons
  $('btn-copy-enc-text').addEventListener('click', async () => {
    const val = $('output-encrypt-text').value;
    if (!val) return;
    try {
      await navigator.clipboard.writeText(val);
      showNotification('encrypt', 'Encrypted ciphertext copied to clipboard.', 'success');
    } catch {
      showNotification('encrypt', 'Clipboard copy unavailable.', 'error');
    }
  });

  $('btn-download-enc-text').addEventListener('click', () => {
    const val = $('output-encrypt-text').value;
    if (!val) return;
    downloadTextBlob(val, 'encrypted_note.txt');
  });

  $('btn-clear-enc-text').addEventListener('click', () => {
    $('input-encrypt-text').value = '';
    $('output-encrypt-text').value = '';
    $('text-encrypt-success-box').style.display = 'none';
    $('text-chars-count').textContent = '0 Chars';
    $('text-bytes-count').textContent = '0 Bytes (UTF-8)';
  });

  // Decrypt Text Mode Toggles
  const toggleDecFile = $('toggle-decrypt-file');
  const toggleDecText = $('toggle-decrypt-text');
  const panelDecFile = $('panel-decrypt-file');
  const panelDecText = $('panel-decrypt-text');
  const btnRunDecrypt = $('btn-run-decrypt');

  toggleDecFile.addEventListener('click', () => {
    state.decryptContentType = 'file';
    toggleDecFile.classList.add('active');
    toggleDecText.classList.remove('active');
    panelDecFile.style.display = 'block';
    panelDecText.style.display = 'none';
    $('text-decrypt-success-box').style.display = 'none';
    btnRunDecrypt.querySelector('span').textContent = 'Decrypt & Verify Integrity';
  });

  toggleDecText.addEventListener('click', () => {
    state.decryptContentType = 'text';
    toggleDecText.classList.add('active');
    toggleDecFile.classList.remove('active');
    panelDecText.style.display = 'block';
    panelDecFile.style.display = 'none';
    $('decrypt-success-box').style.display = 'none';
    btnRunDecrypt.querySelector('span').textContent = 'Decrypt Text Note';
  });

  $('btn-copy-dec-text').addEventListener('click', async () => {
    const val = $('output-decrypt-text').value;
    if (!val) return;
    try {
      await navigator.clipboard.writeText(val);
      showNotification('decrypt', 'Decrypted plaintext copied to clipboard.', 'success');
    } catch {
      showNotification('decrypt', 'Clipboard copy unavailable.', 'error');
    }
  });

  $('btn-download-dec-text').addEventListener('click', () => {
    const val = $('output-decrypt-text').value;
    if (!val) return;
    downloadTextBlob(val, 'decrypted_note.txt');
  });

  $('btn-clear-dec-text').addEventListener('click', () => {
    $('input-decrypt-text').value = '';
    $('output-decrypt-text').value = '';
    $('text-decrypt-success-box').style.display = 'none';
  });
}

async function executeTextEncryption() {
  const plainText = $('input-encrypt-text').value;
  if (!plainText || !plainText.trim()) {
    showNotification('encrypt', 'Please enter a text note to encrypt.', 'error');
    return;
  }

  const keyText = $('input-encrypt-key').value.trim();
  if (!keyText) {
    showNotification('encrypt', 'Please enter or generate an 8-byte DES key.', 'error');
    return;
  }

  let keyBytes;
  try {
    if (state.encryptKeyFormat === 'passphrase') {
      keyBytes = await deriveKeyFromPassphrase(keyText);
    } else {
      keyBytes = parseDesKey(keyText, state.encryptKeyFormat);
    }
  } catch (err) {
    showNotification('encrypt', err.message, 'error');
    return;
  }

  hideNotification('encrypt');
  try {
    const result = await encryptTextNote({
      plainText,
      keyBytes,
      mode: state.encryptMode,
      outputFormat: state.textOutputFormat
    });

    state.encryptedTextResult = result;
    $('output-encrypt-text').value = result.formattedOutput;
    $('text-enc-status').textContent = `DES-${result.mode} Encrypted (${result.outputFormat.toUpperCase()}) ✓`;
    $('text-encrypt-success-box').style.display = 'block';

    addHistoryEntry({
      operation: 'ENCRYPT',
      filename: 'secret_note.txt',
      fileSize: result.originalSizeBytes,
      mode: result.mode,
      hashHex: result.hashHex,
      status: 'SUCCESS'
    });
    updateDashboardStats();
    showNotification('encrypt', 'Text note successfully encrypted with DES!', 'success');
  } catch (err) {
    showNotification('encrypt', `Text encryption failed: ${err.message}`, 'error');
  }
}

async function executeTextDecryption() {
  const encText = $('input-decrypt-text').value.trim();
  if (!encText) {
    showNotification('decrypt', 'Please paste an encrypted Base64 or Hex note.', 'error');
    return;
  }

  const keyText = $('input-decrypt-key').value.trim();
  if (!keyText) {
    showNotification('decrypt', 'Please enter your matching DES key.', 'error');
    return;
  }

  let keyBytes;
  try {
    if (/^[0-9a-fA-F]{16}$/.test(keyText)) {
      keyBytes = parseDesKey(keyText, 'hex');
    } else {
      keyBytes = parseDesKey(keyText, 'ascii');
    }
  } catch (err) {
    showNotification('decrypt', err.message, 'error');
    return;
  }

  hideNotification('decrypt');
  try {
    const result = await decryptTextNote({
      encryptedString: encText,
      keyBytes
    });

    state.decryptedTextResult = result;
    $('output-decrypt-text').value = result.plainText;
    $('text-dec-status').textContent = `Integrity Verified ✓ (${result.charCount} chars, ${result.byteCount} bytes)`;
    $('text-decrypt-success-box').style.display = 'block';

    addHistoryEntry({
      operation: 'DECRYPT',
      filename: 'restored_note.txt',
      fileSize: result.byteCount,
      mode: result.mode,
      hashHex: result.hashHex,
      status: 'SUCCESS'
    });
    updateDashboardStats();
    showNotification('decrypt', 'Text note decrypted successfully and verified!', 'success');
  } catch (err) {
    showNotification('decrypt', err.message, 'error');
    $('text-decrypt-success-box').style.display = 'none';

    addHistoryEntry({
      operation: 'DECRYPT',
      filename: 'text_note.txt',
      fileSize: 0,
      mode: 'CBC',
      status: 'FAILED',
      errorReason: err.message
    });
  }
}

// ==========================================
// TEXT VAULT STUDIO CONTROLLER
// ==========================================
function loadTextIntoVault(text) {
  const tvPlain = $('tv-input-plain');
  if (tvPlain) {
    tvPlain.value = text;
    updateTextVaultTelemetry(text);
  }
  const encTextInput = $('input-encrypt-text');
  if (encTextInput) {
    encTextInput.value = text;
    encTextInput.dispatchEvent(new Event('input'));
  }
}

function updateTextVaultTelemetry(text) {
  const chars = text ? text.length : 0;
  const bytes = text ? new TextEncoder().encode(text).length : 0;
  const blocks = bytes === 0 ? 1 : Math.floor(bytes / 8) + 1;
  const padding = 8 - (bytes % 8);

  if ($('tv-chars-count')) $('tv-chars-count').textContent = `${chars.toLocaleString()} Chars`;
  if ($('tv-bytes-count')) $('tv-bytes-count').textContent = `${bytes.toLocaleString()} Bytes (UTF-8)`;
  if ($('tv-blocks-count')) $('tv-blocks-count').textContent = `${blocks.toLocaleString()} DES Blocks`;
  if ($('tv-padding-count')) $('tv-padding-count').textContent = `${padding} PKCS#7 Pad Bytes`;
}

function showTextNotification(elId, msg, type = 'info') {
  const el = $(elId);
  if (!el) return;
  el.textContent = msg;
  el.className = `notification-banner show notif-${type}`;
  setTimeout(() => {
    el.className = 'notification-banner';
  }, 4000);
}

function setupTextVaultStudioHandlers() {
  const tvPlain = $('tv-input-plain');
  if (tvPlain) {
    tvPlain.addEventListener('input', () => {
      updateTextVaultTelemetry(tvPlain.value);
    });
  }

  $('tv-load-memo')?.addEventListener('click', () => {
    if (SAMPLE_TEXTS && SAMPLE_TEXTS[0]) loadTextIntoVault(SAMPLE_TEXTS[0].text);
  });
  $('tv-load-token')?.addEventListener('click', () => {
    if (SAMPLE_TEXTS && SAMPLE_TEXTS[1]) loadTextIntoVault(SAMPLE_TEXTS[1].text);
  });
  $('tv-clear-plain')?.addEventListener('click', () => {
    if (tvPlain) {
      tvPlain.value = '';
      updateTextVaultTelemetry('');
    }
    if ($('tv-cipher-box')) $('tv-cipher-box').style.display = 'none';
  });

  let tvKeyFmt = 'ascii';
  const tabAscii = $('tv-key-tab-ascii');
  const tabHex = $('tv-key-tab-hex');
  const tvKeyInput = $('tv-input-key');

  tabAscii?.addEventListener('click', () => {
    tvKeyFmt = 'ascii';
    tabAscii.classList.add('active');
    tabHex.classList.remove('active');
    if (tvKeyInput) {
      tvKeyInput.placeholder = 'Enter 8-character key (e.g. MyKey123)';
      tvKeyInput.maxLength = 8;
    }
  });

  tabHex?.addEventListener('click', () => {
    tvKeyFmt = 'hex';
    tabHex.classList.add('active');
    tabAscii.classList.remove('active');
    if (tvKeyInput) {
      tvKeyInput.placeholder = 'Enter 16 hex digits (e.g. 0123456789ABCDEF)';
      tvKeyInput.maxLength = 16;
    }
  });

  const generateTvKey = () => {
    const rawBytes = generateRandomKey();
    if (tvKeyInput) {
      if (tvKeyFmt === 'hex') {
        tvKeyInput.value = bytesToHex(rawBytes);
      } else {
        const safeChars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%';
        let str = '';
        for (let i = 0; i < 8; i++) {
          str += safeChars.charAt(rawBytes[i] % safeChars.length);
        }
        tvKeyInput.value = str;
      }
      tvKeyInput.type = 'text';
      if ($('tv-btn-toggle-key')) $('tv-btn-toggle-key').textContent = 'Hide Key';
    }
  };

  $('tv-btn-gen-key')?.addEventListener('click', generateTvKey);
  // Initial key generation
  generateTvKey();

  $('tv-btn-toggle-key')?.addEventListener('click', () => {
    if (!tvKeyInput) return;
    const isPass = tvKeyInput.type === 'password';
    tvKeyInput.type = isPass ? 'text' : 'password';
    $('tv-btn-toggle-key').textContent = isPass ? 'Hide Key' : 'Show Key';
  });

  $('tv-btn-copy-key')?.addEventListener('click', async () => {
    if (!tvKeyInput || !tvKeyInput.value) return;
    try {
      await navigator.clipboard.writeText(tvKeyInput.value);
      showTextNotification('tv-enc-notification', 'DES Key copied to clipboard!', 'success');
    } catch {
      showTextNotification('tv-enc-notification', 'Clipboard unavailable.', 'error');
    }
  });

  let tvMode = MODE_CBC;
  const btnCbc = $('tv-mode-cbc');
  const btnEcb = $('tv-mode-ecb');
  btnCbc?.addEventListener('click', () => {
    tvMode = MODE_CBC;
    btnCbc.classList.add('active');
    btnEcb.classList.remove('active');
  });
  btnEcb?.addEventListener('click', () => {
    tvMode = MODE_ECB;
    btnEcb.classList.add('active');
    btnCbc.classList.remove('active');
  });

  let tvFmt = 'base64';
  const btnB64 = $('tv-fmt-b64');
  const btnHex = $('tv-fmt-hex');
  btnB64?.addEventListener('click', () => {
    tvFmt = 'base64';
    btnB64.classList.add('active');
    btnHex.classList.remove('active');
  });
  btnHex?.addEventListener('click', () => {
    tvFmt = 'hex';
    btnHex.classList.add('active');
    btnB64.classList.remove('active');
  });

  $('tv-btn-encrypt')?.addEventListener('click', async () => {
    const plainText = tvPlain ? tvPlain.value : '';
    if (!plainText || !plainText.trim()) {
      showTextNotification('tv-enc-notification', 'Please enter a text note to encrypt.', 'error');
      return;
    }
    const keyVal = tvKeyInput ? tvKeyInput.value.trim() : '';
    if (!keyVal) {
      showTextNotification('tv-enc-notification', 'Please enter or generate an 8-byte DES key.', 'error');
      return;
    }

    let keyBytes;
    try {
      keyBytes = parseDesKey(keyVal, tvKeyFmt);
    } catch (err) {
      showTextNotification('tv-enc-notification', err.message, 'error');
      return;
    }

    try {
      const result = await encryptTextNote({
        plainText,
        keyBytes,
        mode: tvMode,
        outputFormat: tvFmt
      });

      if ($('tv-output-cipher')) $('tv-output-cipher').value = result.formattedOutput;
      if ($('tv-enc-status')) $('tv-enc-status').textContent = `DES-${result.mode} Encrypted (${result.outputFormat.toUpperCase()}) ✓`;
      if ($('tv-cipher-box')) $('tv-cipher-box').style.display = 'block';

      addHistoryEntry({
        operation: 'ENCRYPT',
        filename: 'secret_note.txt',
        fileSize: result.originalSizeBytes,
        mode: result.mode,
        hashHex: result.hashHex,
        status: 'SUCCESS'
      });
      updateDashboardStats();
      showTextNotification('tv-enc-notification', 'Text note successfully encrypted with DES!', 'success');
    } catch (err) {
      showTextNotification('tv-enc-notification', `Encryption failed: ${err.message}`, 'error');
    }
  });

  $('tv-btn-copy-cipher')?.addEventListener('click', async () => {
    const cipher = $('tv-output-cipher')?.value;
    if (!cipher) return;
    try {
      await navigator.clipboard.writeText(cipher);
      showTextNotification('tv-enc-notification', 'Ciphertext copied to clipboard!', 'success');
    } catch {
      showTextNotification('tv-enc-notification', 'Clipboard unavailable.', 'error');
    }
  });

  $('tv-btn-send-to-dec')?.addEventListener('click', () => {
    const cipher = $('tv-output-cipher')?.value;
    if (!cipher) return;
    const decCipherInput = $('tv-input-cipher');
    const decKeyInput = $('tv-dec-input-key');
    if (decCipherInput) decCipherInput.value = cipher;
    if (decKeyInput && tvKeyInput) decKeyInput.value = tvKeyInput.value;
    showTextNotification('tv-dec-notification', 'Ciphertext & matching key transferred to Decrypt panel!', 'success');
    decCipherInput?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  });

  $('tv-btn-download-cipher')?.addEventListener('click', () => {
    const cipher = $('tv-output-cipher')?.value;
    if (!cipher) return;
    downloadTextBlob(cipher, 'encrypted_note.txt');
  });

  $('tv-clear-dec')?.addEventListener('click', () => {
    if ($('tv-input-cipher')) $('tv-input-cipher').value = '';
    if ($('tv-output-plain')) $('tv-output-plain').value = '';
    if ($('tv-plain-box')) $('tv-plain-box').style.display = 'none';
  });

  $('tv-btn-sync-key')?.addEventListener('click', () => {
    if (tvKeyInput && $('tv-dec-input-key')) {
      $('tv-dec-input-key').value = tvKeyInput.value;
      showTextNotification('tv-dec-notification', 'Transferred encryption key.', 'success');
    }
  });

  $('tv-btn-toggle-dec-key')?.addEventListener('click', () => {
    const input = $('tv-dec-input-key');
    if (!input) return;
    const isPass = input.type === 'password';
    input.type = isPass ? 'text' : 'password';
    $('tv-btn-toggle-dec-key').textContent = isPass ? 'Hide Key' : 'Show Key';
  });

  $('tv-btn-decrypt')?.addEventListener('click', async () => {
    const encStr = $('tv-input-cipher')?.value.trim();
    if (!encStr) {
      showTextNotification('tv-dec-notification', 'Please paste ciphertext note to decrypt.', 'error');
      return;
    }
    const decKeyVal = $('tv-dec-input-key')?.value.trim();
    if (!decKeyVal) {
      showTextNotification('tv-dec-notification', 'Please enter your matching DES key.', 'error');
      return;
    }

    let keyBytes;
    try {
      if (/^[0-9a-fA-F]{16}$/.test(decKeyVal)) {
        keyBytes = parseDesKey(decKeyVal, 'hex');
      } else {
        keyBytes = parseDesKey(decKeyVal, 'ascii');
      }
    } catch (err) {
      showTextNotification('tv-dec-notification', err.message, 'error');
      return;
    }

    try {
      const result = await decryptTextNote({
        encryptedString: encStr,
        keyBytes
      });

      if ($('tv-output-plain')) $('tv-output-plain').value = result.plainText;
      if ($('tv-dec-status')) $('tv-dec-status').textContent = `Integrity Verified ✓ (${result.charCount} chars, ${result.byteCount} bytes)`;
      if ($('tv-plain-box')) $('tv-plain-box').style.display = 'block';

      addHistoryEntry({
        operation: 'DECRYPT',
        filename: 'restored_note.txt',
        fileSize: result.byteCount,
        mode: result.mode,
        hashHex: result.hashHex,
        status: 'SUCCESS'
      });
      updateDashboardStats();
      showTextNotification('tv-dec-notification', 'Text note successfully decrypted and verified!', 'success');
    } catch (err) {
      showTextNotification('tv-dec-notification', err.message, 'error');
      if ($('tv-plain-box')) $('tv-plain-box').style.display = 'none';
    }
  });

  $('tv-btn-copy-plain')?.addEventListener('click', async () => {
    const plain = $('tv-output-plain')?.value;
    if (!plain) return;
    try {
      await navigator.clipboard.writeText(plain);
      showTextNotification('tv-dec-notification', 'Restored note copied to clipboard!', 'success');
    } catch {
      showTextNotification('tv-dec-notification', 'Clipboard unavailable.', 'error');
    }
  });

  $('tv-btn-download-plain')?.addEventListener('click', () => {
    const plain = $('tv-output-plain')?.value;
    if (!plain) return;
    downloadTextBlob(plain, 'restored_note.txt');
  });
}

// ==========================================
// INITIALIZATION
// ==========================================
window.addEventListener('DOMContentLoaded', () => {
  renderSampleChips();
  setupDashboardQuickDrops();
  setupEncryptHandlers();
  setupDecryptHandlers();
  setupTextModeHandlers();
  setupTextVaultStudioHandlers();
  setupLabHandlers();
  setupInspectorHandlers();
  setupHistoryHandlers();
  setupModalHandlers();
  updateDashboardStats();
  generateAndSetEncryptKey();
});


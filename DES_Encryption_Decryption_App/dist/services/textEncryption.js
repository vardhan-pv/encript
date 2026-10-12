import { encryptCBC, decryptCBC, encryptECB, decryptECB, generateRandomIV, MODE_CBC, MODE_ECB } from '../crypto/des/modes.js';
import { computeSHA256 } from '../crypto/des/hash.js';
import { calculateEntropy } from '../crypto/des/entropy.js';
import { bytesToHex, hexToBytes } from '../crypto/des/keyManager.js';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });

// Magic byte marker for Text Note containers: "DVLTNOTE" (8 bytes)
const NOTE_MAGIC = new Uint8Array([0x44, 0x56, 0x4C, 0x54, 0x4E, 0x4F, 0x54, 0x45]);

/**
 * Encodes Uint8Array into standard Base64 string.
 */
export function bytesToBase64(bytes) {
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i += 8192) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
  }
  return btoa(binary);
}

/**
 * Decodes Base64 string into Uint8Array.
 */
export function base64ToBytes(base64Str) {
  const clean = base64Str.trim().replace(/\s+/g, '');
  const binary = atob(clean);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Encrypts an arbitrary Unicode text string using DES.
 * Returns Base64 or Hex encoded ciphertext package with IV and SHA-256 fingerprint.
 */
export async function encryptTextNote({
  plainText,
  keyBytes,
  mode = MODE_CBC,
  outputFormat = 'base64' // 'base64' | 'hex'
}) {
  if (!plainText || typeof plainText !== 'string') {
    throw new Error('Please enter text to encrypt.');
  }
  if (keyBytes.length !== 8) {
    throw new Error('DES key must be exactly 8 bytes.');
  }

  const plainBytes = textEncoder.encode(plainText);
  const { hex: hashHex, bytes: hashBytes } = await computeSHA256(plainBytes);
  const { entropy } = calculateEntropy(plainBytes);

  const isCBC = mode === MODE_CBC;
  const iv = isCBC ? generateRandomIV() : new Uint8Array(8);

  let cipherBytes;
  if (isCBC) {
    cipherBytes = await encryptCBC(plainBytes, keyBytes, iv);
  } else {
    cipherBytes = await encryptECB(plainBytes, keyBytes);
  }

  // Text Note Package Format:
  // [0..7]   : Magic 'DVLTNOTE' (8 bytes)
  // [8]      : Mode (1 = CBC, 2 = ECB)
  // [9..16]  : IV (8 bytes)
  // [17..48] : SHA-256 (32 bytes)
  // [49..]   : Ciphertext
  const packageBytes = new Uint8Array(49 + cipherBytes.length);
  packageBytes.set(NOTE_MAGIC, 0);
  packageBytes[8] = isCBC ? 1 : 2;
  packageBytes.set(iv, 9);
  packageBytes.set(hashBytes, 17);
  packageBytes.set(cipherBytes, 49);

  let formattedOutput = '';
  if (outputFormat === 'hex') {
    formattedOutput = bytesToHex(packageBytes);
  } else {
    formattedOutput = bytesToBase64(packageBytes);
  }

  return {
    formattedOutput,
    outputFormat,
    originalLengthChars: plainText.length,
    originalSizeBytes: plainBytes.length,
    cipherSizeBytes: cipherBytes.length,
    hashHex,
    entropy,
    mode,
    iv: bytesToHex(iv)
  };
}

/**
 * Decrypts an encrypted text package (Base64 or Hex).
 * Validates integrity and returns the original Unicode text.
 */
export async function decryptTextNote({
  encryptedString,
  keyBytes
}) {
  if (!encryptedString || typeof encryptedString !== 'string') {
    throw new Error('Please paste an encrypted text note.');
  }
  if (keyBytes.length !== 8) {
    throw new Error('DES key must be exactly 8 bytes.');
  }

  const clean = encryptedString.trim().replace(/\s+/g, '');
  let packageBytes;

  // Auto-detect format: Hex (even hex digits) or Base64
  if (/^[0-9a-fA-F]{98,}$/.test(clean)) {
    // Hex package
    packageBytes = hexToBytes(clean);
  } else {
    // Base64 package
    try {
      packageBytes = base64ToBytes(clean);
    } catch {
      throw new Error('Invalid input format. Paste a valid Base64 or Hexadecimal encrypted note.');
    }
  }

  // Check Magic Signature
  let isPackaged = packageBytes.length >= 49;
  if (isPackaged) {
    for (let i = 0; i < 8; i++) {
      if (packageBytes[i] !== NOTE_MAGIC[i]) {
        isPackaged = false;
        break;
      }
    }
  }

  let mode = MODE_CBC;
  let iv = new Uint8Array(8);
  let expectedHashHex = null;
  let cipherBytes;

  if (isPackaged) {
    const modeId = packageBytes[8];
    mode = modeId === 1 ? MODE_CBC : MODE_ECB;
    iv = packageBytes.slice(9, 17);
    const hashBytes = packageBytes.slice(17, 49);
    expectedHashHex = bytesToHex(hashBytes);
    cipherBytes = packageBytes.slice(49);
  } else {
    // Legacy / Raw payload (assume IV [8 bytes] + ciphertext)
    if (packageBytes.length < 16 || packageBytes.length % 8 !== 0) {
      throw new Error('Invalid ciphertext length. Must be a valid 8-byte multiple.');
    }
    iv = packageBytes.slice(0, 8);
    cipherBytes = packageBytes.slice(8);
  }

  if (cipherBytes.length === 0 || cipherBytes.length % 8 !== 0) {
    throw new Error('Corrupted note ciphertext length.');
  }

  let plainBytes;
  try {
    if (mode === MODE_CBC) {
      plainBytes = await decryptCBC(cipherBytes, keyBytes, iv);
    } else {
      plainBytes = await decryptECB(cipherBytes, keyBytes);
    }
  } catch (err) {
    throw new Error(`Decryption failed: Incorrect DES key or damaged note content. (${err.message})`);
  }

  // Recalculate SHA-256
  const { hex: restoredHashHex } = await computeSHA256(plainBytes);
  if (expectedHashHex && restoredHashHex !== expectedHashHex) {
    throw new Error('Integrity verification failed! Decrypted text does not match the original hash.');
  }

  // Decode UTF-8 string
  let plainText = '';
  try {
    plainText = textDecoder.decode(plainBytes);
  } catch {
    throw new Error('Could not decode decrypted bytes as UTF-8 text. Key was likely incorrect.');
  }

  return {
    plainText,
    charCount: plainText.length,
    byteCount: plainBytes.length,
    hashHex: restoredHashHex,
    mode,
    verified: true
  };
}

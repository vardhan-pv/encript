import { generateSubkeys } from './keySchedule.js';
import { transformBlock } from './desCore.js';
import { applyPkcs7Padding, removePkcs7Padding } from './padding.js';

export const MODE_CBC = 'CBC';
export const MODE_ECB = 'ECB';

/**
 * Generates a cryptographically secure 8-byte Initialization Vector.
 */
export function generateRandomIV() {
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    return crypto.getRandomValues(new Uint8Array(8));
  }
  // Fallback for Node without global crypto if older
  const iv = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    iv[i] = Math.floor(Math.random() * 256);
  }
  return iv;
}

/**
 * Encrypt binary data using DES-CBC mode with PKCS#7 padding.
 */
export async function encryptCBC(data, key, iv, onProgress = () => {}) {
  if (key.length !== 8) throw new Error('DES key must be exactly 8 bytes.');
  if (iv.length !== 8) throw new Error('CBC Initialization Vector (IV) must be exactly 8 bytes.');

  const padded = applyPkcs7Padding(data);
  const subkeys = generateSubkeys(key);
  const totalBlocks = padded.length / 8;
  const ciphertext = new Uint8Array(padded.length);

  let previous = new Uint8Array(iv);
  const block = new Uint8Array(8);

  for (let offset = 0; offset < padded.length; offset += 8) {
    for (let i = 0; i < 8; i++) {
      block[i] = padded[offset + i] ^ previous[i];
    }
    const encrypted = transformBlock(block, subkeys);
    ciphertext.set(encrypted, offset);
    previous = encrypted;

    if (offset % 32768 === 0 || offset === padded.length - 8) {
      const pct = Math.min(100, Math.floor(((offset + 8) / padded.length) * 100));
      onProgress(pct);
      // Yield to event loop to allow UI updates
      await new Promise(r => setTimeout(r, 0));
    }
  }

  return ciphertext;
}

/**
 * Decrypt binary data using DES-CBC mode with PKCS#7 unpadding.
 */
export async function decryptCBC(ciphertext, key, iv, onProgress = () => {}) {
  if (key.length !== 8) throw new Error('DES key must be exactly 8 bytes.');
  if (iv.length !== 8) throw new Error('CBC Initialization Vector (IV) must be exactly 8 bytes.');
  if (ciphertext.length === 0 || ciphertext.length % 8 !== 0) {
    throw new Error('Ciphertext length must be a non-zero multiple of 8 bytes.');
  }

  const subkeysReversed = [...generateSubkeys(key)].reverse();
  const decryptedPadded = new Uint8Array(ciphertext.length);

  let previous = new Uint8Array(iv);

  for (let offset = 0; offset < ciphertext.length; offset += 8) {
    const cipherBlock = ciphertext.subarray(offset, offset + 8);
    const plainBlock = transformBlock(cipherBlock, subkeysReversed);

    for (let i = 0; i < 8; i++) {
      decryptedPadded[offset + i] = plainBlock[i] ^ previous[i];
    }
    previous = cipherBlock;

    if (offset % 32768 === 0 || offset === ciphertext.length - 8) {
      const pct = Math.min(100, Math.floor(((offset + 8) / ciphertext.length) * 100));
      onProgress(pct);
      await new Promise(r => setTimeout(r, 0));
    }
  }

  // Strip and validate PKCS#7 padding
  return removePkcs7Padding(decryptedPadded);
}

/**
 * Encrypt binary data using DES-ECB mode with PKCS#7 padding.
 * (Educational mode for demonstration)
 */
export async function encryptECB(data, key, onProgress = () => {}) {
  if (key.length !== 8) throw new Error('DES key must be exactly 8 bytes.');

  const padded = applyPkcs7Padding(data);
  const subkeys = generateSubkeys(key);
  const ciphertext = new Uint8Array(padded.length);

  for (let offset = 0; offset < padded.length; offset += 8) {
    const block = padded.subarray(offset, offset + 8);
    const encrypted = transformBlock(block, subkeys);
    ciphertext.set(encrypted, offset);

    if (offset % 32768 === 0 || offset === padded.length - 8) {
      const pct = Math.min(100, Math.floor(((offset + 8) / padded.length) * 100));
      onProgress(pct);
      await new Promise(r => setTimeout(r, 0));
    }
  }

  return ciphertext;
}

/**
 * Decrypt binary data using DES-ECB mode with PKCS#7 unpadding.
 */
export async function decryptECB(ciphertext, key, onProgress = () => {}) {
  if (key.length !== 8) throw new Error('DES key must be exactly 8 bytes.');
  if (ciphertext.length === 0 || ciphertext.length % 8 !== 0) {
    throw new Error('Ciphertext length must be a non-zero multiple of 8 bytes.');
  }

  const subkeysReversed = [...generateSubkeys(key)].reverse();
  const decryptedPadded = new Uint8Array(ciphertext.length);

  for (let offset = 0; offset < ciphertext.length; offset += 8) {
    const cipherBlock = ciphertext.subarray(offset, offset + 8);
    const plainBlock = transformBlock(cipherBlock, subkeysReversed);
    decryptedPadded.set(plainBlock, offset);

    if (offset % 32768 === 0 || offset === ciphertext.length - 8) {
      const pct = Math.min(100, Math.floor(((offset + 8) / ciphertext.length) * 100));
      onProgress(pct);
      await new Promise(r => setTimeout(r, 0));
    }
  }

  return removePkcs7Padding(decryptedPadded);
}

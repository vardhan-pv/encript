import { computeSHA256 } from './hash.js';
import { encryptCBC, decryptCBC, encryptECB, decryptECB, generateRandomIV, MODE_CBC, MODE_ECB } from './modes.js';

// Magic bytes 'DVLT' in ASCII: [0x44, 0x56, 0x4C, 0x54]
export const MAGIC_DVLT = new Uint8Array([0x44, 0x56, 0x4C, 0x54]);
export const CURRENT_VERSION = 1;
export const ALGO_DES = 1; // 1 = Single DES FIPS 46-3
export const MODE_ID_CBC = 1;
export const MODE_ID_ECB = 2;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });

/**
 * Sanitizes a filename to protect against path traversal and dangerous characters.
 */
export function sanitizeFilename(rawName) {
  if (!rawName || typeof rawName !== 'string') return 'decrypted_file.bin';
  // Strip paths (Unix and Windows)
  const base = rawName.split(/[/\\]/).pop() || 'decrypted_file.bin';
  // Remove control characters (0x00 - 0x1F and 0x7F) and illegal path characters
  const clean = base.replace(/[\u0000-\u001f\u007f"*:<>?\\|]/g, '').trim();
  // Limit length safely
  return clean.slice(0, 180) || 'decrypted_file.bin';
}

/**
 * Packs metadata and encrypted ciphertext into a standardized .dvlt container.
 */
export async function createVaultContainer({
  fileData,
  keyBytes,
  filename,
  mimeType,
  mode = MODE_CBC,
  onProgress = () => {}
}) {
  if (keyBytes.length !== 8) throw new Error('DES key must be exactly 8 bytes.');

  // 1. Calculate SHA-256 fingerprint of original plaintext
  const { bytes: originalHashBytes, hex: originalHashHex } = await computeSHA256(fileData);

  // 2. Prepare Mode and IV
  const isCBC = mode === MODE_CBC;
  const modeId = isCBC ? MODE_ID_CBC : MODE_ID_ECB;
  const iv = isCBC ? generateRandomIV() : new Uint8Array(8);

  // 3. Encrypt file data
  let ciphertext;
  if (isCBC) {
    ciphertext = await encryptCBC(fileData, keyBytes, iv, onProgress);
  } else {
    ciphertext = await encryptECB(fileData, keyBytes, onProgress);
  }

  // 4. Prepare Metadata JSON
  const safeName = sanitizeFilename(filename);
  const ext = safeName.includes('.') ? safeName.split('.').pop().toLowerCase() : '';
  const metadataObj = {
    filename: safeName,
    extension: ext,
    mimeType: mimeType || 'application/octet-stream',
    originalSize: fileData.length,
    timestamp: Date.now(),
    generator: 'DES Vault v1.0 (Educational Academic System)'
  };

  const metadataBytes = textEncoder.encode(JSON.stringify(metadataObj));
  if (metadataBytes.length > 65535) {
    throw new Error('Metadata exceeds allowable container size.');
  }

  // 5. Container Layout:
  // [0..3]   : Magic 'DVLT' (4 bytes)
  // [4]      : Version (1 byte)
  // [5]      : Algorithm (1 byte, 0x01 = DES)
  // [6]      : Mode (1 byte, 0x01 = CBC, 0x02 = ECB)
  // [7..14]  : IV (8 bytes)
  // [15..46] : SHA-256 (32 bytes)
  // [47..50] : Metadata length (4 bytes UInt32 Big-Endian)
  // [51..51+metaLen-1]: Metadata JSON
  // [remainder]: Ciphertext

  const headerSize = 51 + metadataBytes.length;
  const container = new Uint8Array(headerSize + ciphertext.length);

  container.set(MAGIC_DVLT, 0);
  container[4] = CURRENT_VERSION;
  container[5] = ALGO_DES;
  container[6] = modeId;
  container.set(iv, 7);
  container.set(originalHashBytes, 15);

  const dataView = new DataView(container.buffer, container.byteOffset, container.byteLength);
  dataView.setUint32(47, metadataBytes.length, false); // Big-Endian
  container.set(metadataBytes, 51);
  container.set(ciphertext, headerSize);

  return {
    containerBytes: container,
    originalHashHex,
    encryptedSize: container.length,
    originalSize: fileData.length,
    iv,
    mode,
    filename: safeName
  };
}

/**
 * Inspects a .dvlt container without decrypting.
 * Validates header structure, signature, and extracts metadata.
 */
export function inspectVaultContainer(containerBytes) {
  if (containerBytes.length < 51) {
    throw new Error('File is too small to be a valid DES Vault (.dvlt) container.');
  }

  // Validate Magic Signature 'DVLT'
  for (let i = 0; i < 4; i++) {
    if (containerBytes[i] !== MAGIC_DVLT[i]) {
      throw new Error('Invalid file format. Magic signature does not match DES Vault (.dvlt).');
    }
  }

  const version = containerBytes[4];
  if (version !== 1) {
    throw new Error(`Unsupported container version: ${version}. Only version 1 is supported.`);
  }

  const algoId = containerBytes[5];
  const algorithm = algoId === ALGO_DES ? 'DES (FIPS 46-3)' : 'Unknown Cipher';

  const modeId = containerBytes[6];
  const mode = modeId === MODE_ID_CBC ? MODE_CBC : modeId === MODE_ID_ECB ? MODE_ECB : 'Unknown';

  const iv = containerBytes.slice(7, 15);
  const ivHex = Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

  const hashBytes = containerBytes.slice(15, 47);
  const hashHex = Array.from(hashBytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

  const dataView = new DataView(containerBytes.buffer, containerBytes.byteOffset, containerBytes.byteLength);
  const metadataLength = dataView.getUint32(47, false);

  if (51 + metadataLength > containerBytes.length) {
    throw new Error('Corrupted container: Metadata header exceeds file size.');
  }

  let metadata = {};
  try {
    const metaBytes = containerBytes.slice(51, 51 + metadataLength);
    metadata = JSON.parse(textDecoder.decode(metaBytes));
  } catch (err) {
    throw new Error('Corrupted container: Unable to parse metadata JSON.');
  }

  const headerTotalSize = 51 + metadataLength;
  const ciphertextLength = containerBytes.length - headerTotalSize;

  if (ciphertextLength <= 0 || ciphertextLength % 8 !== 0) {
    throw new Error('Corrupted container: Ciphertext length is not a valid 8-byte block multiple.');
  }

  return {
    version,
    algorithm,
    mode,
    modeId,
    iv,
    ivHex,
    originalHashHex: hashHex,
    originalHashBytes: hashBytes,
    metadata: {
      ...metadata,
      filename: sanitizeFilename(metadata.filename)
    },
    headerSize: headerTotalSize,
    ciphertextLength,
    containerSize: containerBytes.length
  };
}

/**
 * Decrypts a .dvlt container and performs full integrity verification against stored SHA-256 hash.
 */
export async function openVaultContainer(containerBytes, keyBytes, onProgress = () => {}) {
  const inspection = inspectVaultContainer(containerBytes);
  const ciphertext = containerBytes.slice(inspection.headerSize);

  let plaintext;
  try {
    if (inspection.mode === MODE_CBC) {
      plaintext = await decryptCBC(ciphertext, keyBytes, inspection.iv, onProgress);
    } else if (inspection.mode === MODE_ECB) {
      plaintext = await decryptECB(ciphertext, keyBytes, onProgress);
    } else {
      throw new Error(`Unsupported encryption mode: ${inspection.mode}`);
    }
  } catch (err) {
    throw new Error(`Decryption failed: Incorrect DES key or corrupted container data. (${err.message})`);
  }

  // Recalculate SHA-256 of restored plaintext
  const { hex: restoredHashHex } = await computeSHA256(plaintext);

  if (restoredHashHex !== inspection.originalHashHex) {
    throw new Error(
      `Integrity verification FAILED! Recovered file checksum (${restoredHashHex.slice(0, 16)}...) does not match original container fingerprint (${inspection.originalHashHex.slice(0, 16)}...). Decryption aborted.`
    );
  }

  return {
    restoredData: plaintext,
    filename: inspection.metadata.filename,
    extension: inspection.metadata.extension,
    mimeType: inspection.metadata.mimeType,
    originalSize: plaintext.length,
    hashHex: restoredHashHex,
    mode: inspection.mode,
    verified: true
  };
}

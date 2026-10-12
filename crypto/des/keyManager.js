const textEncoder = new TextEncoder();

/**
 * Validates and converts input string into an 8-byte DES key Uint8Array.
 * Supports 'ascii' (8 characters) and 'hex' (16 characters).
 */
export function parseDesKey(value, format = 'ascii') {
  if (!value || typeof value !== 'string') {
    throw new Error('Please enter a DES encryption key.');
  }

  const clean = value.trim();

  if (format === 'hex') {
    if (!/^[0-9a-fA-F]{16}$/.test(clean)) {
      throw new Error('Hexadecimal DES key must be exactly 16 hex digits (0-9, A-F), totaling 64 bits.');
    }
    const bytes = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
      bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  if (format === 'ascii') {
    if (clean.length !== 8) {
      throw new Error(`Text DES key must be exactly 8 characters (current: ${clean.length} chars).`);
    }
    // Check printable ASCII range (32 to 126)
    for (let i = 0; i < clean.length; i++) {
      const code = clean.charCodeAt(i);
      if (code < 32 || code > 126) {
        throw new Error('Text DES key must contain printable ASCII characters.');
      }
    }
    return textEncoder.encode(clean);
  }

  throw new Error(`Unsupported key format: ${format}`);
}

/**
 * Derives an 8-byte DES key from an arbitrary passphrase using PBKDF2 with SHA-256.
 * Salt: fixed domain salt or optional custom salt.
 */
export async function deriveKeyFromPassphrase(passphrase, salt = 'DES_VAULT_ACADEMIC_SALT') {
  if (!passphrase || passphrase.length < 4) {
    throw new Error('Passphrase must be at least 4 characters long.');
  }

  const passBytes = textEncoder.encode(passphrase);
  const saltBytes = textEncoder.encode(salt);

  if (typeof crypto !== 'undefined' && crypto.subtle && crypto.subtle.importKey) {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      passBytes,
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const derivedBuffer = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations: 10000,
        hash: 'SHA-256'
      },
      keyMaterial,
      64 // 64 bits = 8 bytes
    );

    return new Uint8Array(derivedBuffer);
  }

  // Fallback for Node test environments
  try {
    const nodeCrypto = await import('node:crypto');
    const derived = nodeCrypto.pbkdf2Sync(passphrase, salt, 10000, 8, 'sha256');
    return new Uint8Array(derived);
  } catch (err) {
    throw new Error('Key derivation failed: Web Crypto / Node crypto unavailable.');
  }
}

/**
 * Generates a cryptographically secure 8-byte random key.
 */
export function generateRandomKey() {
  const bytes = new Uint8Array(8);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < 8; i++) bytes[i] = Math.floor(Math.random() * 256);
  }

  // Format as Hex
  const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

  // Make an ASCII-friendly version where all bytes are printable ASCII (33-126)
  const asciiBytes = new Uint8Array(8);
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
  let asciiStr = '';
  for (let i = 0; i < 8; i++) {
    const char = chars[bytes[i] % chars.length];
    asciiStr += char;
    asciiBytes[i] = char.charCodeAt(0);
  }

  return {
    rawBytes: bytes,
    hex,
    asciiStr,
    asciiBytes
  };
}

/**
 * Converts byte array to 16-hex character uppercase string.
 */
export function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

/**
 * Converts 16-hex character string to byte array.
 */
export function hexToBytes(hex) {
  const clean = hex.trim();
  const len = clean.length >>> 1;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Generates .deskey export file content.
 */
export function generateKeyfileContent({ keyBytes, keyHex, originalFilename = 'file' }) {
  const hex = keyHex || bytesToHex(keyBytes);
  return `# =========================================================
# DES VAULT — ENCRYPTION KEY EXPORT FILE
# =========================================================
# WARNING:
# Anyone who possesses both this key and your encrypted .dvlt file
# can decrypt the data. Store this key securely.
# =========================================================

TARGET_FILE=${originalFilename}
ALGORITHM=DES (Data Encryption Standard - FIPS 46-3)
KEY_HEX=${hex}
KEY_BITS=64 (56 Effective Bits + 8 Parity Bits)
CREATED_AT=${new Date().toISOString()}
SYSTEM=DES Vault Universal Cryptography Platform
`;
}

/**
 * Parses an uploaded .deskey file content to extract the key hex.
 */
export function parseKeyfileContent(fileText) {
  const match = fileText.match(/KEY_HEX=([0-9a-fA-F]{16})/i);
  if (match) {
    return match[1].toUpperCase();
  }
  // Try raw 16 hex string
  const rawMatch = fileText.trim().match(/^[0-9a-fA-F]{16}$/);
  if (rawMatch) {
    return rawMatch[0].toUpperCase();
  }
  throw new Error('Unable to find a valid 16-character hexadecimal DES key in the uploaded key file.');
}

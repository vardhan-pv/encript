/**
 * PKCS#7 / PKCS#5 Padding for 8-byte block ciphers (DES).
 */

/**
 * Applies PKCS#7 padding to arbitrary binary data.
 * Returns a new Uint8Array whose length is a multiple of 8.
 */
export function applyPkcs7Padding(data) {
  const padLen = 8 - (data.length % 8); // 1 to 8
  const padded = new Uint8Array(data.length + padLen);
  padded.set(data);
  padded.fill(padLen, data.length);
  return padded;
}

/**
 * Validates and removes PKCS#7 padding from decrypted binary data.
 * Throws an error if padding is malformed or invalid.
 */
export function removePkcs7Padding(paddedData) {
  if (!paddedData || paddedData.length === 0 || paddedData.length % 8 !== 0) {
    throw new Error('Data length must be a non-zero multiple of 8 for PKCS#7 unpadding.');
  }

  const padLen = paddedData[paddedData.length - 1];
  if (padLen < 1 || padLen > 8) {
    throw new Error(`Invalid PKCS#7 padding length (${padLen}). Incorrect DES key or corrupted ciphertext.`);
  }

  for (let i = paddedData.length - padLen; i < paddedData.length; i++) {
    if (paddedData[i] !== padLen) {
      throw new Error('Corrupted PKCS#7 padding bytes. Incorrect DES key or corrupted ciphertext.');
    }
  }

  return paddedData.subarray(0, paddedData.length - padLen);
}

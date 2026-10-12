/**
 * SHA-256 Hashing utility supporting both Browser (Web Crypto API) and Node.js environments.
 */

export async function computeSHA256(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);

  // Browser Web Crypto API
  if (typeof crypto !== 'undefined' && crypto.subtle && crypto.subtle.digest) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
    const hashBytes = new Uint8Array(hashBuffer);
    const hex = Array.from(hashBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    return {
      bytes: hashBytes,
      hex: hex.toUpperCase()
    };
  }

  // Node.js fallback
  try {
    const nodeCrypto = await import('node:crypto');
    const hash = nodeCrypto.createHash('sha256').update(bytes).digest();
    const hashBytes = new Uint8Array(hash);
    const hex = hash.toString('hex').toUpperCase();
    return {
      bytes: hashBytes,
      hex
    };
  } catch (err) {
    throw new Error('No crypto engine available to compute SHA-256.');
  }
}

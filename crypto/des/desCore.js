import { IP, FP } from './constants.js';
import { generateSubkeys } from './keySchedule.js';
import { feistelFunction, evaluateFeistelDetailed, int32ToHex, int32ToBinary } from './feistel.js';

/**
 * Extracts a bit from byte array (1-indexed).
 */
function bit(bytes, p) {
  return (bytes[(p - 1) >>> 3] >>> (7 - ((p - 1) & 7))) & 1;
}

/**
 * Transforms an 8-byte block using subkeys.
 * Core DES loop using precomputed SP table.
 */
export function transformBlock(block, subkeys) {
  // Initial Permutation (IP)
  let l = 0;
  let r = 0;
  for (let i = 0; i < 32; i++) {
    l = (l << 1) | bit(block, IP[i]);
    r = (r << 1) | bit(block, IP[i + 32]);
  }
  l >>>= 0;
  r >>>= 0;

  // 16 Feistel rounds
  for (let round = 0; round < 16; round++) {
    const f = feistelFunction(r, subkeys[round]);
    const nextR = (l ^ f) >>> 0;
    l = r;
    r = nextR;
  }

  // Final Permutation (FP / IP^-1)
  // Note: Standard Feistel leaves (R16, L16) before FP.
  // In the loop above, after 16 iterations:
  // l contains R16, r contains L16.
  // FP takes R16 as left half (bits 1..32) and L16 as right half (bits 33..64).
  const out = new Uint8Array(8);
  for (let i = 0; i < 64; i++) {
    const p = FP[i];
    // In DES Feistel, after round 16, r is R16 (left half for FP) and l is L16 (right half for FP).
    const b = p <= 32 ? (r >>> (32 - p)) & 1 : (l >>> (64 - p)) & 1;
    out[i >>> 3] |= b << (7 - (i & 7));
  }
  return out;
}

/**
 * Encrypt a single 8-byte block using DES.
 */
export function encryptBlock(block, key) {
  if (block.length !== 8) throw new Error('DES input block must be 8 bytes.');
  if (key.length !== 8) throw new Error('DES key must be 8 bytes.');
  const subkeys = generateSubkeys(key);
  return transformBlock(block, subkeys);
}

/**
 * Decrypt a single 8-byte block using DES.
 * Reverses the subkey schedule (K16 down to K1).
 */
export function decryptBlock(block, key) {
  if (block.length !== 8) throw new Error('DES input block must be 8 bytes.');
  if (key.length !== 8) throw new Error('DES key must be 8 bytes.');
  const subkeys = generateSubkeys(key);
  return transformBlock(block, [...subkeys].reverse());
}

/**
 * Educational Full Feistel Trace for DES Lab.
 * Returns every single round and intermediate state for an 8-byte block.
 */
export function traceBlockEncryption(block, key) {
  if (block.length !== 8 || key.length !== 8) {
    throw new Error('Block and key must be 8 bytes.');
  }

  const subkeys = generateSubkeys(key);

  // 1. Raw Input
  let rawBits = '';
  for (let i = 1; i <= 64; i++) {
    rawBits += bit(block, i);
  }

  // 2. Initial Permutation (IP)
  let l = 0;
  let r = 0;
  let ipBits = '';
  for (let i = 0; i < 32; i++) {
    const bL = bit(block, IP[i]);
    l = (l << 1) | bL;
    ipBits += bL;
  }
  for (let i = 0; i < 32; i++) {
    const bR = bit(block, IP[i + 32]);
    r = (r << 1) | bR;
    ipBits += bR;
  }
  l >>>= 0;
  r >>>= 0;

  const rounds = [];
  let currentL = l;
  let currentR = r;

  for (let round = 0; round < 16; round++) {
    const detailed = evaluateFeistelDetailed(currentL, currentR, subkeys[round]);
    rounds.push({
      roundNumber: round + 1,
      ...detailed
    });
    currentL = detailed.newL;
    currentR = detailed.newR;
  }

  // After 16 rounds, currentR is R16 and currentL is L16.
  // Pre-output block before FP is (R16, L16).
  const r16 = currentR;
  const l16 = currentL;

  // Final Permutation (FP)
  const out = new Uint8Array(8);
  let fpBits = '';
  for (let i = 0; i < 64; i++) {
    const p = FP[i];
    const b = p <= 32 ? (r16 >>> (32 - p)) & 1 : (l16 >>> (64 - p)) & 1;
    out[i >>> 3] |= b << (7 - (i & 7));
    fpBits += b;
  }

  const ciphertextHex = Array.from(out).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  const plaintextHex = Array.from(block).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

  return {
    plaintextHex,
    rawBits,
    ipBits,
    l0Hex: int32ToHex(l),
    r0Hex: int32ToHex(r),
    l0Bits: int32ToBinary(l),
    r0Bits: int32ToBinary(r),
    rounds,
    preFpHex: int32ToHex(r16) + int32ToHex(l16),
    fpBits,
    ciphertextHex,
    ciphertextBytes: out
  };
}

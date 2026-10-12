import { E, P, S_BOXES } from './constants.js';

/**
 * Precomputed S-P substitution-permutation table:
 * SP[sboxIndex][6bitInput] -> 32-bit word with P permutation applied.
 * Enables high-performance DES encryption and decryption.
 */
export const SP_TABLE = S_BOXES.map((table, g) => {
  return Array.from({ length: 64 }, (_, x) => {
    // 6-bit input x:
    // row is formed from outermost bits: bit 5 (MSB) and bit 0 (LSB)
    const row = ((x & 32) >>> 4) | (x & 1);
    // col is formed from innermost 4 bits: bits 4, 3, 2, 1
    const col = (x >>> 1) & 15;
    const raw4bits = table[row * 16 + col] << (28 - 4 * g);

    // Apply P-box permutation (32 bits)
    let permuted32 = 0;
    for (let i = 0; i < 32; i++) {
      permuted32 = (permuted32 << 1) | ((raw4bits >>> (32 - P[i])) & 1);
    }
    return permuted32 >>> 0;
  });
});

/**
 * Fast Feistel function F(R, K) applying Expansion, S-Box substitution, and P-permutation.
 * R: 32-bit unsigned integer
 * K: array of 8 integers (each 6 bits)
 * Returns 32-bit unsigned integer.
 */
export function feistelFunction(r, roundKey) {
  let f = 0;
  for (let g = 0; g < 8; g++) {
    // Extract 6 bits using E-table
    let x = 0;
    for (let j = 0; j < 6; j++) {
      x = (x << 1) | ((r >>> (32 - E[g * 6 + j])) & 1);
    }
    // XOR with round subkey group and lookup in precomputed SP table
    f ^= SP_TABLE[g][x ^ roundKey[g]];
  }
  return f >>> 0;
}

/**
 * Formats a 32-bit integer as a 32-character binary string.
 */
export function int32ToBinary(num) {
  return (num >>> 0).toString(2).padStart(32, '0');
}

/**
 * Formats a 32-bit integer as 8-character hex string.
 */
export function int32ToHex(num) {
  return (num >>> 0).toString(16).padStart(8, '0').toUpperCase();
}

/**
 * Educational detailed Feistel round breakdown for DES Lab.
 * Returns all intermediate bitstrings and S-box lookups.
 */
export function evaluateFeistelDetailed(L_prev, R_prev, roundKey) {
  const rBits = int32ToBinary(R_prev);

  // 1. Expansion: 32 bits -> 48 bits
  const expandedBits = [];
  for (let i = 0; i < 48; i++) {
    const bitPos = E[i]; // 1..32
    expandedBits.push(rBits[bitPos - 1]);
  }
  const expandedStr = expandedBits.join('');

  // 2. Round Key: 48 bits from roundKey array of 8 x 6 bits
  const keyBits = [];
  for (let g = 0; g < 8; g++) {
    keyBits.push(roundKey[g].toString(2).padStart(6, '0'));
  }
  const keyStr = keyBits.join('');

  // 3. XOR: Expanded ^ Key (48 bits)
  const xorBits = [];
  for (let i = 0; i < 48; i++) {
    xorBits.push(Number(expandedStr[i]) ^ Number(keyStr[i]));
  }
  const xorStr = xorBits.join('');

  // 4. S-box evaluations (8 S-boxes)
  const sboxDetails = [];
  let sOutput32Raw = 0;

  for (let g = 0; g < 8; g++) {
    const group6 = xorStr.slice(g * 6, (g + 1) * 6);
    const b0 = Number(group6[0]);
    const b5 = Number(group6[5]);
    const row = (b0 << 1) | b5;
    const col = parseInt(group6.slice(1, 5), 2);
    const val4 = S_BOXES[g][row * 16 + col];

    sOutput32Raw = (sOutput32Raw << 4) | val4;

    sboxDetails.push({
      sboxNumber: g + 1,
      input6Bits: group6,
      row,
      col,
      output4Bits: val4.toString(2).padStart(4, '0'),
      outputDec: val4
    });
  }

  const sOutputStr = sboxDetails.map(s => s.output4Bits).join('');

  // 5. P-permutation (32 bits -> 32 bits)
  const pBits = [];
  for (let i = 0; i < 32; i++) {
    pBits.push(sOutputStr[P[i] - 1]);
  }
  const pStr = pBits.join('');
  const pInt = parseInt(pStr, 2) >>> 0;

  // 6. Feistel XOR: L_prev ^ P
  const l_prev_int = L_prev >>> 0;
  const newR = (l_prev_int ^ pInt) >>> 0;
  const newL = R_prev >>> 0;

  return {
    lPrevHex: int32ToHex(l_prev_int),
    rPrevHex: int32ToHex(R_prev),
    expandedBits: expandedStr,
    keyBits: keyStr,
    xorBits: xorStr,
    sboxDetails,
    sOutputBits: sOutputStr,
    pOutputBits: pStr,
    pOutputHex: int32ToHex(pInt),
    newLHex: int32ToHex(newL),
    newRHex: int32ToHex(newR),
    newL,
    newR
  };
}

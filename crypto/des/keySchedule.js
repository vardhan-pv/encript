import { PC1, PC2, SHIFTS } from './constants.js';

/**
 * Extract a specific bit (1-indexed) from a Uint8Array of bytes.
 * Returns 0 or 1.
 */
export function getBit(bytes, bitPos1Indexed) {
  const byteIdx = (bitPos1Indexed - 1) >>> 3;
  const bitOffset = 7 - ((bitPos1Indexed - 1) & 7);
  return (bytes[byteIdx] >>> bitOffset) & 1;
}

/**
 * Converts array of 0/1 bits to binary string.
 */
export function bitsToString(bits) {
  return bits.join('');
}

/**
 * Converts array of 0/1 bits to hexadecimal string.
 */
export function bitsToHex(bits) {
  let hex = '';
  for (let i = 0; i < bits.length; i += 4) {
    const nibble = (bits[i] << 3) | (bits[i + 1] << 2) | (bits[i + 2] << 1) | bits[i + 3];
    hex += nibble.toString(16).toUpperCase();
  }
  return hex;
}

/**
 * Standard fast key schedule returning 16 subkeys as array of 8 integers (each representing 6 bits).
 * This format allows high-performance Feistel round evaluation.
 */
export function generateSubkeys(keyBytes) {
  if (keyBytes.length !== 8) {
    throw new Error('DES key must be exactly 8 bytes (64 bits).');
  }

  // Permuted Choice 1 (PC-1): 64 bits -> 56 bits
  const bits = PC1.map(p => getBit(keyBytes, p));
  let c = bits.slice(0, 28);
  let d = bits.slice(28);

  const subkeys = [];

  for (let round = 0; round < 16; round++) {
    const shift = SHIFTS[round];
    // Left circular shift
    c = c.slice(shift).concat(c.slice(0, shift));
    d = d.slice(shift).concat(d.slice(0, shift));

    const cd = c.concat(d);

    // Permuted Choice 2 (PC-2): 56 bits -> 48 bits
    // Group into 8 groups of 6 bits for S-Box lookups
    const roundKeyGroups = [];
    for (let g = 0; g < 8; g++) {
      let val = 0;
      for (let j = 0; j < 6; j++) {
        val = (val << 1) | cd[PC2[g * 6 + j] - 1];
      }
      roundKeyGroups.push(val);
    }
    subkeys.push(roundKeyGroups);
  }

  return subkeys;
}

/**
 * Educational Key Schedule Trace generator for the DES Lab.
 * Returns step-by-step breakdown of parity bit removal, C/D registers, shifts, and subkeys.
 */
export function generateKeyScheduleTrace(keyBytes) {
  if (keyBytes.length !== 8) {
    throw new Error('DES key must be exactly 8 bytes (64 bits).');
  }

  // 1. Raw 64 bits
  const rawBits = [];
  for (let i = 1; i <= 64; i++) {
    rawBits.push(getBit(keyBytes, i));
  }

  // Parity bits at positions 8, 16, 24, 32, 40, 48, 56, 64
  const parityBits = [8, 16, 24, 32, 40, 48, 56, 64].map(pos => ({
    pos,
    bit: rawBits[pos - 1]
  }));

  // 2. PC-1 (56 bits)
  const pc1Bits = PC1.map(p => getBit(keyBytes, p));
  let c = pc1Bits.slice(0, 28);
  let d = pc1Bits.slice(28);

  const initialC0 = [...c];
  const initialD0 = [...d];

  const rounds = [];

  for (let round = 0; round < 16; round++) {
    const shift = SHIFTS[round];
    c = c.slice(shift).concat(c.slice(0, shift));
    d = d.slice(shift).concat(d.slice(0, shift));
    const cd = c.concat(d);

    // PC-2 (48 bits)
    const kBits = PC2.map(p => cd[p - 1]);
    const kHex = bitsToHex(kBits);

    // 8 groups of 6 bits
    const groups = [];
    for (let g = 0; g < 8; g++) {
      groups.push(kBits.slice(g * 6, (g + 1) * 6).join(''));
    }

    rounds.push({
      roundNumber: round + 1,
      shift,
      cBits: bitsToString(c),
      dBits: bitsToString(d),
      cdBits: bitsToString(cd),
      kBits: bitsToString(kBits),
      kHex,
      groups
    });
  }

  return {
    rawBits: bitsToString(rawBits),
    parityBits,
    pc1Bits: bitsToString(pc1Bits),
    c0: bitsToString(initialC0),
    d0: bitsToString(initialD0),
    rounds
  };
}

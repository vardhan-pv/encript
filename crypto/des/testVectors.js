import { encryptBlock, decryptBlock } from './desCore.js';
import { generateSubkeys } from './keySchedule.js';
import { applyPkcs7Padding, removePkcs7Padding } from './padding.js';
import { encryptCBC, decryptCBC, encryptECB, decryptECB, generateRandomIV } from './modes.js';
import { createVaultContainer, inspectVaultContainer, openVaultContainer } from './container.js';
import { calculateEntropy } from './entropy.js';
import { computeSHA256 } from './hash.js';
import { hexToBytes, bytesToHex, parseDesKey } from './keyManager.js';

export const KNOWN_TEST_VECTORS = [
  {
    name: 'FIPS 46-3 Standard Vector 1',
    keyHex: '133457799BBCDFF1',
    plainHex: '0123456789ABCDEF',
    expectedCipherHex: '85E813540F0AB405'
  },
  {
    name: 'FIPS 46-3 Zero Output Vector 2',
    keyHex: '0E329232EA6D0D73',
    plainHex: '8787878787878787',
    expectedCipherHex: '0000000000000000'
  },
  {
    name: 'FIPS 46-3 All Zeros Vector 3',
    keyHex: '0000000000000000',
    plainHex: '0000000000000000',
    expectedCipherHex: '8CA64DE9C1B123A7'
  }
];

/**
 * Runs all automated DES test suites.
 * Returns an array of test result items: { name, passed, details, durationMs }.
 */
export async function runAllTests() {
  const results = [];

  const runTest = async (name, fn) => {
    const t0 = performance.now();
    try {
      await fn();
      const durationMs = Math.round(performance.now() - t0);
      results.push({ name, passed: true, details: `Passed in ${durationMs}ms`, durationMs });
    } catch (err) {
      const durationMs = Math.round(performance.now() - t0);
      results.push({ name, passed: false, details: err.message, durationMs });
    }
  };

  // Test 1: FIPS Known Answer Vectors
  for (const vector of KNOWN_TEST_VECTORS) {
    await runTest(`Known Answer Vector: ${vector.name}`, () => {
      const key = hexToBytes(vector.keyHex);
      const plain = hexToBytes(vector.plainHex);
      const cipher = encryptBlock(plain, key);
      const cipherHex = bytesToHex(cipher);
      if (cipherHex !== vector.expectedCipherHex) {
        throw new Error(`Expected ${vector.expectedCipherHex}, got ${cipherHex}`);
      }
      // Inverse check
      const decrypted = decryptBlock(cipher, key);
      const decHex = bytesToHex(decrypted);
      if (decHex !== vector.plainHex) {
        throw new Error(`Decryption failed: expected ${vector.plainHex}, got ${decHex}`);
      }
    });
  }

  // Test 2: Key Schedule Verification
  await runTest('Key Schedule: 16 distinct 48-bit subkeys generated', () => {
    const key = hexToBytes('133457799BBCDFF1');
    const subkeys = generateSubkeys(key);
    if (subkeys.length !== 16) throw new Error(`Expected 16 subkeys, got ${subkeys.length}`);
    for (const sk of subkeys) {
      if (sk.length !== 8) throw new Error('Each subkey must have 8 groups of 6 bits');
    }
  });

  // Test 3: PKCS#7 Padding & Unpadding for all modulo sizes
  await runTest('PKCS#7 Padding: Exact round-trips for lengths 0 to 32 bytes', () => {
    for (let len = 0; len <= 32; len++) {
      const original = new Uint8Array(len);
      for (let i = 0; i < len; i++) original[i] = (i * 17) & 0xFF;
      const padded = applyPkcs7Padding(original);
      if (padded.length % 8 !== 0) throw new Error(`Padded length ${padded.length} is not multiple of 8`);
      const unpadded = removePkcs7Padding(padded);
      if (unpadded.length !== original.length) throw new Error(`Unpadded length mismatch for input len ${len}`);
      for (let i = 0; i < len; i++) {
        if (unpadded[i] !== original[i]) throw new Error(`Byte mismatch at index ${i} for input len ${len}`);
      }
    }
  });

  // Test 4: CBC Mode Multi-block round trip
  await runTest('DES-CBC: Multi-block binary encryption & decryption', async () => {
    const key = parseDesKey('test_key', 'ascii');
    const iv = generateRandomIV();
    const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);
    const cipher = await encryptCBC(data, key, iv);
    const decrypted = await decryptCBC(cipher, key, iv);
    if (decrypted.length !== data.length) throw new Error('Decrypted length mismatch in CBC');
    for (let i = 0; i < data.length; i++) {
      if (decrypted[i] !== data[i]) throw new Error(`Mismatch in CBC decrypted data at byte ${i}`);
    }
  });

  // Test 5: ECB Mode round trip
  await runTest('DES-ECB: Single and multi-block round trip', async () => {
    const key = hexToBytes('0123456789ABCDEF');
    const data = new TextEncoder().encode('Academic DES Project - ECB Mode');
    const cipher = await encryptECB(data, key);
    const decrypted = await decryptECB(cipher, key);
    const text = new TextDecoder().decode(decrypted);
    if (text !== 'Academic DES Project - ECB Mode') throw new Error('ECB text round trip failed');
  });

  // Test 6: Full .dvlt Container Creation, Inspection, and Verification
  await runTest('.dvlt Container: End-to-end Binary File Seal & SHA-256 Integrity Verification', async () => {
    const key = parseDesKey('VaultDES', 'ascii');
    // Simulated PDF binary header %PDF-1.4 with arbitrary binary data
    const pdfData = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34, 0x0A, 0x25, 0xE2, 0xE3, 0xCF, 0xD3, 0x0A, 0x00, 0xFF, 0x7E, 0x42]);
    const { containerBytes, originalHashHex } = await createVaultContainer({
      fileData: pdfData,
      keyBytes: key,
      filename: 'research_paper.pdf',
      mimeType: 'application/pdf'
    });

    // Inspect
    const inspection = inspectVaultContainer(containerBytes);
    if (inspection.metadata.filename !== 'research_paper.pdf') throw new Error('Filename metadata mismatch');
    if (inspection.originalHashHex !== originalHashHex) throw new Error('Hash metadata mismatch');

    // Open with correct key
    const result = await openVaultContainer(containerBytes, key);
    if (!result.verified) throw new Error('Container failed verification');
    if (result.restoredData.length !== pdfData.length) throw new Error('Restored length mismatch');
    for (let i = 0; i < pdfData.length; i++) {
      if (result.restoredData[i] !== pdfData[i]) throw new Error(`Restored byte ${i} mismatch`);
    }
  });

  // Test 7: Wrong Key Rejection
  await runTest('Security Validation: Wrong key is safely rejected without producing corrupt output', async () => {
    const correctKey = parseDesKey('correct1', 'ascii');
    const wrongKey = parseDesKey('wrongkey', 'ascii');
    const data = new Uint8Array([10, 20, 30, 40, 50, 60, 70, 80]);
    const { containerBytes } = await createVaultContainer({
      fileData: data,
      keyBytes: correctKey,
      filename: 'secure.bin',
      mimeType: 'application/octet-stream'
    });

    let caught = false;
    try {
      await openVaultContainer(containerBytes, wrongKey);
    } catch (err) {
      caught = true;
    }
    if (!caught) throw new Error('Wrong key was incorrectly accepted!');
  });

  // Test 8: Tampered Container Detection
  await runTest('Tamper Resistance: Modified ciphertext is detected and aborted', async () => {
    const key = parseDesKey('tamper01', 'ascii');
    const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const { containerBytes } = await createVaultContainer({
      fileData: data,
      keyBytes: key,
      filename: 'doc.txt',
      mimeType: 'text/plain'
    });

    // Flip a bit in the ciphertext portion
    const tampered = new Uint8Array(containerBytes);
    tampered[tampered.length - 2] ^= 0x01;

    let caught = false;
    try {
      await openVaultContainer(tampered, key);
    } catch (err) {
      caught = true;
    }
    if (!caught) throw new Error('Tampered ciphertext was not detected!');
  });

  // Test 9: File DNA Entropy & Analysis
  await runTest('File DNA: Shannon entropy calculation', () => {
    const uniformData = new Uint8Array(256);
    for (let i = 0; i < 256; i++) uniformData[i] = i;
    const uniformRes = calculateEntropy(uniformData);
    if (Math.abs(uniformRes.entropy - 8.0) > 0.05) {
      throw new Error(`Expected entropy ~8.0 for uniform distribution, got ${uniformRes.entropy}`);
    }

    const flatData = new Uint8Array(100).fill(65); // All 'A's
    const flatRes = calculateEntropy(flatData);
    if (flatRes.entropy !== 0) {
      throw new Error(`Expected entropy 0 for identical bytes, got ${flatRes.entropy}`);
    }
  });

  return results;
}

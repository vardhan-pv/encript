import assert from 'node:assert/strict';
import { encryptBlock, decryptBlock } from './dist/crypto/des/desCore.js';
import { generateSubkeys } from './dist/crypto/des/keySchedule.js';
import { encryptCBC, decryptCBC, encryptECB, decryptECB, generateRandomIV } from './dist/crypto/des/modes.js';
import { createVaultContainer, inspectVaultContainer, openVaultContainer } from './dist/crypto/des/container.js';
import { computeSHA256 } from './dist/crypto/des/hash.js';
import { parseDesKey, bytesToHex, hexToBytes, generateRandomKey } from './dist/crypto/des/keyManager.js';
import { SAMPLE_FILES } from './dist/services/samples.js';

console.log('=== DES Vault Universal Verification Test Suite ===\n');

// 1. FIPS 46-3 Official Known Answer Vector
const knownKey = hexToBytes('133457799BBCDFF1');
const knownPlain = hexToBytes('0123456789ABCDEF');
const expectedCipher = '85E813540F0AB405';

const actualCipher = encryptBlock(knownPlain, knownKey);
assert.equal(bytesToHex(actualCipher), expectedCipher, 'Known answer cipher vector must match FIPS 46-3');
assert.deepEqual(decryptBlock(actualCipher, knownKey), knownPlain, 'Inverse decryption must recover exact plaintext');
console.log('✓ PASS: FIPS 46-3 Known Answer Test Vector (85E813540F0AB405) & Inverse Block Decryption');

// 2. Key Parsing & Validation
assert.deepEqual(parseDesKey('133457799BBCDFF1', 'hex'), knownKey);
assert.equal(parseDesKey('mykey123', 'ascii').length, 8);
for (const invalid of ['short', 'toolongkey123', 'invalid!@#\u0000', '']) {
  assert.throws(() => parseDesKey(invalid, 'ascii'));
}
assert.throws(() => parseDesKey('ZZ3457799BBCDFF1', 'hex'));
console.log('✓ PASS: Strict Key Validation (8-char ASCII & 16-digit Hexadecimal)');

// 3. Binary File Format Round-Trips (PDF, PNG, ZIP, TXT)
const testKey = parseDesKey('VaultDES', 'ascii');

for (const sample of SAMPLE_FILES) {
  const originalBytes = sample.getData();
  const { hex: originalHash } = await computeSHA256(originalBytes);

  // Seal into .dvlt container
  const { containerBytes } = await createVaultContainer({
    fileData: originalBytes,
    keyBytes: testKey,
    filename: sample.name,
    mimeType: sample.mimeType
  });

  // Inspect container metadata without decrypting
  const inspection = inspectVaultContainer(containerBytes);
  assert.equal(inspection.metadata.filename, sample.name);
  assert.equal(inspection.originalHashHex, originalHash);
  assert.equal(inspection.version, 1);

  // Decrypt with matching key
  const opened = await openVaultContainer(containerBytes, testKey);
  assert.equal(opened.verified, true);
  assert.equal(opened.hashHex, originalHash);
  assert.deepEqual(opened.restoredData, originalBytes, `Decrypted ${sample.name} must be 100% byte-for-byte identical to original`);

  // Verify wrong key fails safely
  const wrongKey = parseDesKey('wrongkey', 'ascii');
  await assert.rejects(
    () => openVaultContainer(containerBytes, wrongKey),
    /Decryption failed|Integrity verification FAILED/,
    'Wrong key must be rejected without creating output'
  );

  console.log(`✓ PASS: Universal Binary Round-Trip: ${sample.name} (${originalBytes.length} bytes, SHA-256: ${originalHash.slice(0, 16)}...)`);
}

// 4. Randomized IV & Multi-block CBC Consistency
for (let n = 0; n <= 32; n++) {
  const data = new Uint8Array(n);
  for (let i = 0; i < n; i++) data[i] = (i * 31) & 0xff;
  const iv = generateRandomIV();
  const cipher = await encryptCBC(data, testKey, iv);
  const recovered = await decryptCBC(cipher, testKey, iv);
  assert.deepEqual(recovered, data);
}
console.log('✓ PASS: Multi-block DES-CBC & PKCS#7 Padding Round-Trips across lengths 0 to 32 bytes');

// 5. Tamper Resistance
const testData = new Uint8Array([10, 20, 30, 40, 50, 60, 70, 80]);
const { containerBytes } = await createVaultContainer({
  fileData: testData,
  keyBytes: testKey,
  filename: 'tamper_test.bin',
  mimeType: 'application/octet-stream'
});

const tamperedContainer = new Uint8Array(containerBytes);
tamperedContainer[tamperedContainer.length - 1] ^= 0x01; // flip single bit in ciphertext
await assert.rejects(
  () => openVaultContainer(tamperedContainer, testKey),
  /Decryption failed|Integrity verification FAILED/,
  'Flipped ciphertext bit must be caught by padding or SHA-256 verification'
);
console.log('✓ PASS: Cryptographic Tamper Resistance (Bit flip safely aborted)');

// 6. High-Throughput Performance Benchmark
const benchSize = 128 * 1024; // 128 KiB binary payload
const benchData = new Uint8Array(benchSize);
for (let i = 0; i < benchSize; i++) benchData[i] = i & 0xff;

const t0 = performance.now();
const { containerBytes: benchContainer } = await createVaultContainer({
  fileData: benchData,
  keyBytes: testKey,
  filename: 'benchmark.bin',
  mimeType: 'application/octet-stream'
});
const encryptMs = Math.round(performance.now() - t0);

const t1 = performance.now();
const benchRecovered = await openVaultContainer(benchContainer, testKey);
const decryptMs = Math.round(performance.now() - t1);

assert.deepEqual(benchRecovered.restoredData, benchData);
console.log(`✓ PASS: 128 KiB Universal Binary Benchmark — Encryption: ${encryptMs}ms, Decryption: ${decryptMs}ms (${Math.round((benchSize / 1024) / (encryptMs / 1000))} KB/s)`);

console.log('\nAll DES Vault verification tests PASSED with 100% integrity!');

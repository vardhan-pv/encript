import { runAllTests } from '../crypto/des/testVectors.js';

console.log('=== Running DES Vault Automated Verification Tests ===\n');

try {
  const results = await runAllTests();
  let passedCount = 0;
  for (const r of results) {
    if (r.passed) {
      passedCount++;
      console.log(`[PASS] ${r.name} (${r.durationMs}ms)`);
    } else {
      console.error(`[FAIL] ${r.name}: ${r.details}`);
    }
  }
  console.log(`\nResults: ${passedCount} / ${results.length} tests passed.`);
  if (passedCount !== results.length) {
    process.exit(1);
  }
} catch (err) {
  console.error('Fatal test error:', err);
  process.exit(1);
}

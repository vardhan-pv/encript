/**
 * Shannon Entropy and Byte Distribution Analyzer for arbitrary binary data.
 */

export function calculateEntropy(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  if (bytes.length === 0) {
    return {
      entropy: 0,
      interpretation: 'Empty (0 bits/byte)',
      frequencies: new Array(256).fill(0),
      uniqueBytes: 0
    };
  }

  // Count byte occurrences (0..255)
  const counts = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) {
    counts[bytes[i]]++;
  }

  let entropy = 0;
  const total = bytes.length;
  let uniqueBytes = 0;

  for (let i = 0; i < 256; i++) {
    if (counts[i] > 0) {
      uniqueBytes++;
      const p = counts[i] / total;
      entropy -= p * Math.log2(p);
    }
  }

  let interpretation = '';
  if (entropy > 7.5) {
    interpretation = 'High Entropy (Encrypted, compressed, or high-randomness binary data)';
  } else if (entropy > 5.5) {
    interpretation = 'Medium-High Entropy (Compiled binary, document container, or media)';
  } else if (entropy > 3.5) {
    interpretation = 'Moderate Entropy (Structured code, HTML, JSON, or formatted text)';
  } else if (entropy > 1.5) {
    interpretation = 'Low-Moderate Entropy (Plain ASCII text, uncompressed scripts)';
  } else {
    interpretation = 'Low Entropy (Highly repetitive or sparse binary patterns)';
  }

  return {
    entropy: Number(entropy.toFixed(3)),
    interpretation,
    frequencies: Array.from(counts),
    uniqueBytes
  };
}

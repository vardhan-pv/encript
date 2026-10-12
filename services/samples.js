/**
 * Pre-packaged sample binary and text files for academic demonstration and testing.
 */

// Valid 16x16 transparent/colored PNG image binary bytes
// (Valid PNG structure: Signature + IHDR + IDAT + IEND chunks)
const samplePngBase64 =
  'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAA7SURBVDhPY/wPBAwUAGYSF4A0oxuAzSVIg7GZgWwAyGYYHgytABqE4WkgxXQY2QBUAwwUBoMTA11hMAA1xQE3fHlZ6AAAAABJRU5ErkJggg==';

// Valid minimal PDF document with catalog, pages, font, and text
const samplePdfText = `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< /Length 87 >>
stream
BT
/F1 20 Tf
70 700 Td
(DES Vault: Universal Binary File Encryption System) Tj
ET
endstream
endobj
5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000244 00000 n 
0000000382 00000 n 
trailer
<< /Size 6 /Root 1 0 R >>
startxref
451
%%EOF`;

// Valid minimal empty ZIP file (End of Central Directory Record)
const sampleZipBytes = new Uint8Array([
  0x50, 0x4B, 0x05, 0x06, // End of Central Directory signature
  0x00, 0x00,             // Number of this disk
  0x00, 0x00,             // Disk where central directory starts
  0x00, 0x00,             // Number of central directory records on this disk
  0x00, 0x00,             // Total number of central directory records
  0x00, 0x00, 0x00, 0x00, // Size of central directory (0 bytes)
  0x00, 0x00, 0x00, 0x00, // Offset of start of central directory
  0x00, 0x00              // ZIP comment length
]);

function base64ToUint8(b64) {
  if (typeof atob !== 'undefined') {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

export const SAMPLE_FILES = [
  {
    id: 'sample-txt',
    name: 'cybersecurity_briefing.txt',
    mimeType: 'text/plain',
    typeDescription: 'ASCII / UTF-8 Text',
    getData: () =>
      new TextEncoder().encode(
        `# CYBERSECURITY ACADEMIC BRIEFING: DATA ENCRYPTION STANDARD (DES)
Date: October 2026
Topic: Feistel Network & 56-Bit Block Cipher Analysis

DES was standardized in 1977 as FIPS 46-3 by NIST (then NBS) based on IBM's Lucifer cipher.
- Block Size: 64 bits (8 bytes)
- Key Size: 64 bits (56 effective bits + 8 parity bits)
- Rounds: 16 Feistel rounds with 8 non-linear S-boxes

This file tests arbitrary text encryption, PKCS#7 padding validation, and SHA-256 fingerprint verification.`
      )
  },
  {
    id: 'sample-pdf',
    name: 'fips46_whitepaper.pdf',
    mimeType: 'application/pdf',
    typeDescription: 'PDF Document',
    getData: () => new TextEncoder().encode(samplePdfText)
  },
  {
    id: 'sample-png',
    name: 'classified_schematic.png',
    mimeType: 'image/png',
    typeDescription: 'PNG Binary Image',
    getData: () => base64ToUint8(samplePngBase64)
  },
  {
    id: 'sample-zip',
    name: 'audit_archive.zip',
    mimeType: 'application/zip',
    typeDescription: 'ZIP Compressed Binary',
    getData: () => sampleZipBytes
  }
];

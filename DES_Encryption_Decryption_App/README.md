# DES Encryption & Decryption Application

Single DES implemented from scratch in JavaScript. Includes note and file encryption/decryption, text or hexadecimal keys, random CBC IVs, PKCS#7 padding, Base64 notes, downloads and a responsive interface. No AES or Triple DES encryption is used.

## Run locally

Requires Python 3 for the local web server. No packages need to be installed.

1. Extract this ZIP.
2. Open a terminal in the DES_Encryption_Decryption_App folder.
3. Run:

   python -m http.server 8000 --bind 127.0.0.1 --directory dist

   On Windows, use `py` instead of `python` if needed.
4. Open http://localhost:8000 in a modern browser.

Do not open index.html directly: ES modules require a web server.

Windows: double-click start_windows.bat for the same local server.

## Demo

1. Select Encrypt and Text note.
2. Enter: Hello DES
3. Select Text key format and enter mykey123 in both key fields.
4. Encrypt and copy the Base64 result.
5. Select Decrypt, paste the result, and use mykey123 again.
6. Decrypt to restore the note.

For files, select File, choose a file up to 20 MiB, encrypt, and download the .desvault package. To restore it, select Decrypt and File, choose the downloaded package, enter the same key and download the restored file. Downloaded encrypted notes can also be decrypted using the File workflow.

Hexadecimal keys must contain exactly 16 hex digits, for example 133457799BBCDFF1. Text keys must contain exactly 8 printable ASCII characters. DES ignores one parity bit per key byte, leaving 56 effective key bits.

## Source files

- dist/index.html: user interface and instructions
- dist/style.css: responsive styling
- dist/app.mjs: interface actions, key validation and downloads
- dist/crypto.mjs: DES permutations, 16-round Feistel cipher, S-boxes, key schedule, CBC, padding and package format
- dist/favicon.svg: application icon
- verify.mjs: verification script

## Verification

Requires Node.js 20 or later and OpenSSL 3 with its legacy provider available:

    node verify.mjs

The script verifies the known DES block vector (key 133457799BBCDFF1, plaintext 0123456789ABCDEF, ciphertext 85E813540F0AB405), inverse decryption, key validation, Unicode notes, binary and empty files, random IVs, all padding lengths, invalid inputs and selected wrong-key failures. CBC outputs are cross-checked against OpenSSL for several input lengths. If OpenSSL is missing, the final independent comparison requires installing it; the preceding JavaScript checks can still run.

## Package format

Binary .desvault packages contain the ASCII marker CVDES001, an 8-byte random IV, then DES-CBC ciphertext. The padded plaintext contains a 4-byte big-endian JSON metadata length, JSON metadata (kind and original filename), then original file or note bytes. Notes displayed in the interface encode the entire binary package as Base64.

Only this app's DES packages are supported. Earlier AES packages and arbitrary raw DES ciphertext cannot be opened.

## Hosting

Upload the contents of dist to an HTTPS static hosting service. No backend, database, account system or environment keys are required. No content or DES key is uploaded by this application. Your inputs and results are not persisted between page reloads.

## Security limitations

DES is obsolete and is suitable only for educational demonstrations. Do not use it for sensitive real-world information. CBC has no authentication: modified ciphertext may decrypt to modified data, and wrong keys are not guaranteed to be detected. The app has not had an independent security audit. Save the same DES key to decrypt your result; there is no key recovery.

NIST specification and withdrawal notice: https://csrc.nist.gov/pubs/fips/46-3/final

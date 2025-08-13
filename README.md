# Sammanet Secure Web Server

An alternative, minimal web server designed to serve regular internet traffic while performing on-the-fly page encryption. Pages are authored in Markdown-like files, converted to HTML on the server, encrypted with AES-256-GCM, and delivered to clients with a client-side decryptor implemented in WebCrypto.

## What you’ll find
- index.js: Minimal Node.js server implementing page encryption, page extraction, and a simple upload/download flow.
- pages/: Directory containing Markdown-like pages (e.g., home.md) that are converted to HTML and encrypted.
- data/uploads/: Encrypted uploads are stored here.
- data/uploads_meta/: Metadata for encrypted uploads.
- README.md: This file.

## Key concepts implemented
- On-the-fly encryption: Server converts Markdown-like pages to HTML, then encrypts using AES-256-GCM.
- Client-side decryption: The browser runs a small WebCrypto-based decryptor to render the plaintext HTML.
- Per-page metadata in HTML: Each page embeds a per-page key, IV, ciphertext, and authentication tag in the final HTML, enabling client-side decryption.
- Lightweight Markdown-to-HTML: A minimal converter turns Markdown-like syntax into basic HTML.
- Custom blocks: Pages can contain preserved custom blocks like <snet-script> and <snet-style> that are carried through extraction and optionally reinjected into final HTML.

## How it works (high level)
- Pages are authored in ./pages (e.g., hello.md).
- When a user requests /page/<name>, the server:
  - Reads the Markdown file.
  - Extracts optional blocks (<snet-script>, <snet-style>).
  - Converts remaining content from Markdown-like syntax to HTML.
  - Encrypts the HTML with AES-256-GCM (server-side).
  - Returns a final HTML document that includes a small inlined decryptor and the encrypted payload data (key, iv, ct, tag) for client-side decryption.
- Uploads are encrypted server-side only; downloads decrypt on the server before sending raw bytes.

## Directory structure
- index.js: Core server logic (routing, encryption, decryption helper, sample page initialization).
- pages/
  - hello.md: Sample page (generated if missing).
- data/uploads/: Encrypted uploads (.enc.json)
- data/uploads_meta/: Upload metadata (.meta.json)
- .env: Environment variables (if used)

## Getting started
1. Ensure Node.js is installed (the project uses built-in Node.js crypto, http, fs, and path modules).
2. Run the server:
   - node index.js
+      - Note: index.js includes enhanced filtering for scripting and styling blocks (<snet-script> and <snet-style>). These blocks are sanitized during extraction and can be reinjected into the final HTML according to configuration.
3. Open http://localhost:7742 in your browser.
4. Explore:
   - GET /: Page index with links to available pages and endpoints.
   - GET /page/<name>: Render an encrypted page (decryptor runs in the browser to reveal content).
   - POST /upload: Upload a file (expects JSON: { filename, data: base64 } and a token), example:
   ```bash
   curl -X POST http://localhost:7742/upload -H "Content-Type: application/json" -H "Authorization: Bearer <TOKEN>" -d '{"filename":"test.bin","data":"BASE64_CONTENT"}'
    ```
   - GET /download/<filename>: Download and decrypt a stored encrypted file.

## Security notes
- Per-page encryption keys and parameters (key, iv, ct, tag) are embedded in the final HTML in a hidden element and exposed to the browser. The client-side decryptor uses WebCrypto to decrypt using these values.
- Uploads/downloads are encryption-based demonstrations with no authentication. Do not rely on this for real secret handling or regulated data without adding proper auth, auditing, and key management. Feel free to disable these.
- TLS and transport security considerations are not explicitly demonstrated here; enable TLS in real deployments and model threat vectors accordingly.

## Limitations and caveats
- Embedding the encryption key in the HTML means access to the page HTML equates to access to the plaintext content in this model.
- The per-page decryptor is embedded into the page, and the overall security model relies on the browser’s WebCrypto API and the integrity of the delivered HTML. Real security requires more robust key management, TLS, and threat modeling.
- Upload/download security is basic; there is no authentication, and file sizes are limited to prevent DOSing.

## Extending and contributing
- Add more pages in the pages/ directory with Markdown-like syntax.
- Enhance the MD-to-HTML converter to cover more markdown features as needed.
- Improve the security model by introducing a stronger separation of concerns, stricter CSP, and safer handling of keys (e.g., ephemeral per-page keys with server-side controls and secure key delivery mechanisms).
- Add tests and more robust error handling.

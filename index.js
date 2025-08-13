// Minimal, robust Node.js internet server with on-the-fly page encryption and client-side decryption.
 // - Pages are authored in a lightweight Markdown-like format in ./pages (e.g., hello.md).
 // - Each page is converted to HTML, then encrypted with AES-256-GCM on the server.
 // - The final HTML embeds a per-page key/iv/ct/tag and a small WebCrypto-based decryptor
 //   that runs in the browser to render the plaintext HTML.
 // - Custom <snet-script> and <snet-style> tags found in Markdown are preserved during extraction
 //   and can be optionally reinjected into the final HTML as raw blocks. This is a demonstration
 //   and not production-ready security.
 // - Uploads/downloads of non-page files are encrypted server-side only (no client JS).
 
 const http = require('http');
 const fs = require('fs');
 const path = require('path');
 const crypto = require('crypto');
 
 const PORT = 3000;
 const PAGES_DIR = path.join(__dirname, 'pages');
 const UPLOAD_DIR = path.join(__dirname, 'data', 'uploads');
 const UPLOAD_META_DIR = path.join(__dirname, 'data', 'uploads_meta');
 
 // Ensure required directories exist
 function ensureDir(dir) {
   if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
 }
 ensureDir(PAGES_DIR);
 ensureDir(UPLOAD_DIR);
 ensureDir(UPLOAD_META_DIR);
 
 // Minimal HTML escaping to prevent basic injection
 function escapeHtml(s) {
   if (typeof s !== 'string') return '';
   return s
     .replace(/&/g, '&')
     .replace(/</g, '<')
     .replace(/>/g, '>')
     .replace(/"/g, '"')
     .replace(/'/g, '&#39;');
 }
 
 // Very lightweight Markdown-like converter
 function mdToHtml(md) {
   const lines = md.split(/\r?\n/);
   let html = '';
   for (let line of lines) {
     if (line.startsWith('# ')) {
       html += `<h1>${escapeHtml(line.slice(2).trim())}</h1>\n`;
     } else if (line.startsWith('## ')) {
       html += `<h2>${escapeHtml(line.slice(3).trim())}</h2>\n`;
     } else if (line.trim().length === 0) {
       // preserve blank lines
       html += '\n';
     } else {
       html += `<p>${escapeHtml(line.trim())}</p>\n`;
     }
   }
   return html;
 }
 
 // Robust extraction of custom blocks using simple scanners
 function extractBlocks(rawMd) {
   const snetScripts = [];
   const snetStyles = [];
 
   // Extract <snet-script> blocks
   let md = rawMd;
   const openScript = '<snet-script>';
   const closeScript = '</snet-script>';
   let idx = md.indexOf(openScript);
   while (idx !== -1) {
     const start = idx + openScript.length;
     const end = md.indexOf(closeScript, start);
     if (end === -1) break;
     snetScripts.push(md.substring(start, end));
     md = md.substring(0, idx) + md.substring(end + closeScript.length);
     idx = md.indexOf(openScript);
   }
 
   // Extract <snet-style> blocks
   const openStyle = '<snet-style>';
   const closeStyle = '</snet-style>';
   idx = md.indexOf(openStyle);
   while (idx !== -1) {
     const start = idx + openStyle.length;
     const end = md.indexOf(closeStyle, start);
     if (end === -1) break;
     snetStyles.push(md.substring(start, end));
     md = md.substring(0, idx) + md.substring(end + closeStyle.length);
     idx = md.indexOf(openStyle);
   }
 
   return { md, snetScripts, snetStyles };
 }
 
 // Encrypt HTML content server-side
 function encryptHtml(html) {
   const key = crypto.randomBytes(32); // AES-256
   const iv = crypto.randomBytes(12);  // GCM nonce
   const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
   let ct = cipher.update(Buffer.from(html, 'utf8'));
   ct = Buffer.concat([ct, cipher.final()]);
   const tag = cipher.getAuthTag();
   return {
     key: key.toString('base64'),
     iv: iv.toString('base64'),
     ct: ct.toString('base64'),
     tag: tag.toString('base64')
   };
 }
 
 // Simple decrypt helper for server-side (used only for uploads/downloads if needed)
 function decryptHtmlEncrypted(payload) {
   const key = Buffer.from(payload.key, 'base64');
   const iv = Buffer.from(payload.iv, 'base64');
   const ct = Buffer.from(payload.ct, 'base64');
   const tag = Buffer.from(payload.tag, 'base64');
   const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
   decipher.setAuthTag(tag);
   let html = decipher.update(ct);
   html = Buffer.concat([html, decipher.final()]);
   return html.toString('utf8');
 }
 
 // Initialize with a sample page if none exist
 function ensureSamplePage() {
   const files = fs.existsSync(PAGES_DIR) ? fs.readdirSync(PAGES_DIR) : [];
   const mdFiles = files.filter((f) => f.endsWith('.md'));
   if (mdFiles.length === 0) {
     const sample = [
       '# Welcome to Sammanet Server',
       '',
       'This is a sample page. It will be encrypted server-side and decrypted client-side.',
       '',
       '<snet-style>',
       '/* Sample styles injected from <snet-style> blocks (preserved) */',
       'body { font-family: Arial, sans-serif; background: #f6f6f6; color: #333; }',
       '</snet-style>',
       '',
       '<snet-script>',
       '// Sanitized content in <snet-script>; this is preserved as a raw script block in the final HTML.',
       '</snet-script>',
       '',
       'Enjoy exploring encryption-in-page-demo.'
     ].join('\\n');
     fs.writeFileSync(path.join(PAGES_DIR, 'hello.md'), sample, 'utf8');
   }
 }
 
 // Build the final HTML for a page: final HTML includes decryptor script
 function buildEncryptedPageHtml(pageName, payload, stylesHtml, snetScripts) {
   const ctB64 = payload.ct;
   const ivB64 = payload.iv;
   const keyB64 = payload.key;
   const tagB64 = payload.tag;
 
   const scriptBlocks = (snetScripts && snetScripts.length)
     ? snetScripts.map((s) => `<script>${s}</script>`).join('\\n')
     : '';
 
   // Simple decrypted HTML injection
   const html = `
 <!DOCTYPE html>
 <html>
 <head>
   <meta charset="utf-8" />
   <title>${escapeHtml(pageName)}</title>
   ${stylesHtml ? `<style>${stylesHtml}</style>` : ''}
   ${scriptBlocks}
   <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;">
 </head>
 <body>
   <div id="content">
     <p>Decrypting content, please wait...</p>
   </div>
 
   <div id="sn-encrypted"
        data-ct="${ctB64}"
        data-iv="${ivB64}"
        data-key="${keyB64}"
        data-tag="${tagB64}"
        style="display:none;"
   ></div>
 
   <script>
   (function() {
     function b64ToBytes(b64) {
       const bin = atob(b64);
       const len = bin.length;
       const bytes = new Uint8Array(len);
       for (let i = 0; i < len; i++) bytes[i] = bin.charCodeAt(i);
       return bytes;
     }
 
     function concat(a, b) {
       const c = new Uint8Array(a.length + b.length);
       c.set(a, 0);
       c.set(b, a.length);
       return c;
     }
 
     async function decryptAndRender() {
       try {
         const el = document.getElementById('sn-encrypted');
         const ct = b64ToBytes(el.dataset.ct);
         const iv = b64ToBytes(el.dataset.iv);
         const keyBytes = b64ToBytes(el.dataset.key);
         const tag = b64ToBytes(el.dataset.tag);
 
         const ciphertext = concat(ct, tag);
 
         const cryptoKey = await crypto.subtle.importKey(
           'raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']
         );
 
         const plaintextBuf = await crypto.subtle.decrypt(
           { name: 'AES-GCM', iv: iv },
           cryptoKey,
           ciphertext
         );
 
         const html = new TextDecoder().decode(plaintextBuf);
         document.getElementById('content').innerHTML = html;
       } catch (e) {
         document.getElementById('content').textContent = 'Decryption failed or content unavailable.';
         console.error('Decryption error:', e);
       }
     }
 
     if (document.readyState === 'loading') {
       document.addEventListener('DOMContentLoaded', decryptAndRender);
     } else {
       decryptAndRender();
     }
   })();
   </script>
 </body>
 </html>
 `.trim();
   return html;
 }
 
 // Helper to avoid syntax issues with windowed value in template
 function naked(v) {
   return v;
 }
 
 // Simple router
 function route(req, res) {
   const { method, url } = req;
 
   function respondHtml(status, html) {
     res.writeHead(status, {
       'Content-Type': 'text/html',
       'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
     });
     res.end(html);
   }
 
   if (url === '/' && method === 'GET') {
     let pageList = [];
     try {
       const files = fs.existsSync(PAGES_DIR) ? fs.readdirSync(PAGES_DIR) : [];
       pageList = files.filter((f) => f.endsWith('.md')).map((f) => f.replace(/\\.md$/, ''));
     } catch (e) {
       pageList = [];
     }
     const body = `<html><body><h1>Sammanet Server</h1><ul>${
       pageList.map((p) => `<li><a href="/page/${encodeURIComponent(p)}">${escapeHtml(p)}</a></li>`).join('')
     }</ul>
     <p>Endpoints:</p>
     <ul>
       <li>View page: GET /page/<name></li>
       <li>Upload file: POST /upload (JSON: { filename, data: base64 })</li>
       <li>Download file: GET /download/<filename></li>
     </ul></body></html>`;
     respondHtml(200, body);
     return;
   }
 
   if (url.startsWith('/page/') && method === 'GET') {
     const name = decodeURIComponent(url.substring('/page/'.length));
     const mdPath = path.join(PAGES_DIR, name.endsWith('.md') ? name : name + '.md');
     if (!fs.existsSync(mdPath)) {
       res.writeHead(404, { 'Content-Type': 'text/plain' });
       res.end('Page not found');
       return;
     }
 
     const rawMd = fs.readFileSync(mdPath, 'utf8');
     const { md, snetScripts, snetStyles } = extractBlocks(rawMd);
     const contentHtml = mdToHtml(md);
     const stylesHtml = snetStyles.length > 0 ? snetStyles.join('\\n') : '';
 
     const payload = encryptHtml(contentHtml);
     const finalHtml = buildEncryptedPageHtml(name, payload, stylesHtml, snetScripts);
 
     respondHtml(200, finalHtml);
     return;
   }
 
   if (url.startsWith('/upload') && method === 'POST') {
     let body = '';
     req.on('data', (chunk) => {
       body += chunk;
       if (body.length > 1e6) req.destroy();
     });
     req.on('end', () => {
       try {
         const j = JSON.parse(body);
         const filename = (j.filename || 'upload.bin').toString();
         const safeName = path.basename(filename);
         const payloadBase64 = String(j.data || '');
         const fileBytes = Buffer.from(payloadBase64, 'base64');
 
         const MAX_BYTES = 1024 * 1024;
         if (fileBytes.length > MAX_BYTES) {
           res.writeHead(413, { 'Content-Type': 'application/json' });
           res.end(JSON.stringify({ ok: false, error: 'file too large' }));
           return;
         }
 
         const key = crypto.randomBytes(32);
         const iv = crypto.randomBytes(12);
         const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
         let ct = cipher.update(fileBytes);
         ct = Buffer.concat([ct, cipher.final()]);
         const tag = cipher.getAuthTag();
 
         const record = {
           key: key.toString('base64'),
           iv: iv.toString('base64'),
           ct: ct.toString('base64'),
           tag: tag.toString('base64')
         };
 
         const outPath = path.join(UPLOAD_DIR, safeName + '.enc.json');
         fs.writeFileSync(outPath, JSON.stringify(record), 'utf8');
 
         const metaPath = path.join(UPLOAD_META_DIR, safeName + '.meta.json');
         fs.writeFileSync(metaPath, JSON.stringify({ originalName: safeName, size: fileBytes.length }), 'utf8');
 
         res.writeHead(200, { 'Content-Type': 'application/json' });
         res.end(JSON.stringify({ ok: true, path: '/uploads/' + safeName }));
       } catch (e) {
         res.writeHead(400, { 'Content-Type': 'application/json' });
         res.end(JSON.stringify({ ok: false, error: (e && e.message) || 'invalid request' }));
       }
     });
     return;
   }
 
   if (url.startsWith('/download/') && method === 'GET') {
     const filename = decodeURIComponent(url.substring('/download/'.length)).toString();
     const safeName = path.basename(filename);
     const encPath = path.join(UPLOAD_DIR, safeName + '.enc.json');
     if (!fs.existsSync(encPath)) {
       res.writeHead(404, { 'Content-Type': 'text/plain' });
       res.end('Encrypted file not found');
       return;
     }
 
     try {
       const payload = JSON.parse(fs.readFileSync(encPath, 'utf8'));
       const key = Buffer.from(payload.key, 'base64');
       const iv = Buffer.from(payload.iv, 'base64');
       const ct = Buffer.from(payload.ct, 'base64');
       const tag = Buffer.from(payload.tag, 'base64');
 
       const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
       decipher.setAuthTag(tag);
       let plaintext = decipher.update(ct);
       plaintext = Buffer.concat([plaintext, decipher.final()]);
 
       const ext = path.extname(safeName) || '.bin';
       const mime = ext === '.md' ? 'text/markdown' : 'application/octet-stream';
       res.writeHead(200, {
         'Content-Type': mime,
         'Content-Disposition': 'attachment; filename="' + safeName + ext + '"'
       });
       res.end(plaintext);
     } catch (e) {
       res.writeHead(500, { 'Content-Type': 'text/plain' });
       res.end('Decryption failed: ' + (e && e.message));
     }
     return;
   }
 
   res.writeHead(404, { 'Content-Type': 'text/plain' });
   res.end('Not Found');
 }
 
 // Ensure sample content exists
 ensureSamplePage();
 
 // Create the HTTP server
 const server = http.createServer((req, res) => {
   route(req, res);
 });
 
 // Start server
 server.listen(PORT, () => {
   console.log('Sammanet-like server listening on http://localhost:' + PORT);
 });

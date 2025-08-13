/*
 Minimal, robust Node.js internet server with on-the-fly page encryption
 - Pages are authored in a lightweight Markdown-like format in ./pages (e.g., hello.md).
 - Each page is converted to HTML, then encrypted with AES-256-GCM on the server.
 - The final HTML embeds a per-page key/iv/ct/tag and a small WebCrypto-based decryptor
   that runs in the browser to render the plaintext HTML.
 - Custom <snet-script> and <snet-style> tags found in Markdown are preserved during extraction
   and can be optionally reinjected into the final HTML as raw blocks. This is a demonstration
   and not production-ready security.
 - Uploads/downloads of non-page files are encrypted server-side only (no client JS).
*/

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = 7742;
const PAGES_DIR = path.join(__dirname, 'pages');
const UPLOAD_DIR = path.join(__dirname, 'data', 'uploads');
const UPLOAD_META_DIR = path.join(__dirname, 'data', 'uploads_meta');

/* Load environment variables from .env if present to support flags like UPLOAD_DOWNLOAD_ENABLED */
function loadEnvFromFile(filePath) {
  try {
    if (!fs.existsSync(filePath)) return;
    const content = fs.readFileSync(filePath, 'utf8');
    content.split(/\r?\n/).forEach((line) => {
      const s = line.trim();
      if (!s || s.startsWith('#')) return;
      const eq = s.indexOf('=');
      if (eq <= 0) return;
      const key = s.substring(0, eq).trim();
      const value = s.substring(eq + 1).trim();
      if (key) process.env[key] = value;
    });
  } catch (e) {
    // ignore errors loading env
  }
}
loadEnvFromFile(path.join(__dirname, '.env'));

function parseBoolEnv(v, defaultValue) {
  if (typeof v === 'undefined') return defaultValue;
  const s = String(v).toLowerCase();
  return s === 'true' || s === '1' || s === 'yes';
}
let UPLOAD_ENABLED = parseBoolEnv(process.env.UPLOAD_ENABLED, true); // enable uploads
let DOWNLOAD_ENABLED = parseBoolEnv(process.env.DOWNLOAD_ENABLED, true); // enable downloads
const UPLOAD_AUTH_ENABLED = parseBoolEnv(process.env.UPLOAD_AUTH_ENABLED, true); // auth guard for uploads
const UPLOAD_TOKEN = process.env.UPLOAD_TOKEN || 'default-upload-token'; // token for uploads authentication

// Optional download authentication
let DOWNLOAD_AUTH_ENABLED = parseBoolEnv(process.env.DOWNLOAD_AUTH_ENABLED, false); // default: disabled
const DOWNLOAD_TOKEN = process.env.DOWNLOAD_TOKEN || 'default-download-token'; // token for downloads authentication

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
function buildEncryptedPageHtml(pageName, payload, stylesHtml, snetScripts, nonce) {
  const ctB64 = payload.ct;
  const ivB64 = payload.iv;
  const keyB64 = payload.key;
  const tagB64 = payload.tag;

  const scriptBlocks = (snetScripts && snetScripts.length)
    ? snetScripts.map((s) => `<script nonce="${nonce}">${s}</script>`).join('\\n')
    : '';

  // The final HTML embeds a decryptor that will run in the browser
  const html = `
 <!DOCTYPE html>
 <html>
 <head>
   <meta charset="utf-8" />
   <title>${escapeHtml(pageName)}</title>
   ${stylesHtml ? `<style nonce="${nonce}">${stylesHtml}</style>` : ''}
   ${scriptBlocks}
   <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:;">
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

   <script nonce="${nonce}">
   (async function() {
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

     try {
       const el = document.getElementById('sn-encrypted');
       const ct = b64ToBytes(el.dataset.ct);
       const iv = b64ToBytes(el.dataset.iv);
       const keyBytes = b64ToBytes(el.dataset.key);
       const tag = b64ToBytes(el.dataset.tag);

       // In AES-GCM, ciphertext is ct || tag
       const ciphertext = concat(ct, tag);

       const cryptoKey = await crypto.subtle.importKey(
         'raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']
       );

       const plaintextBuf = await crypto.subtle.decrypt(
         { name: 'AES-GCM', iv: iv },
         cryptoKey,
         ciphertext
       );

       const decoder = new TextDecoder();
       const html = decoder.decode(plaintextBuf);
       document.getElementById('content').innerHTML = html;
     } catch (e) {
       document.getElementById('content').textContent = 'Decryption failed or content unavailable.';
       console.error('Decryption error:', e);
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

  function respondHtml(status, html, nonce) {
    res.writeHead(status, {
      'Content-Type': 'text/html',
      'Content-Security-Policy': `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:;`
    });
    res.end(html);
  }

  // Root page: index with links to pages and endpoints
  if (url === '/' && method === 'GET') {
    let pageList = [];
    try {
      const files = fs.existsSync(PAGES_DIR) ? fs.readdirSync(PAGES_DIR) : [];
      pageList = files.filter((f) => f.endsWith('.md')).map((f) => f.replace(/\\.md$/, ''));
    } catch (e) {
      pageList = [];
    }

    // Generate a per-request nonce for CSP
    const nonce = crypto.randomBytes(16).toString('base64');

    // Local flags for display
    const downloadAuthLabel = DOWNLOAD_AUTH_ENABLED ? 'ENABLED' : 'DISABLED';
    const downloadTokenLabel = DOWNLOAD_AUTH_ENABLED ? (DOWNLOAD_TOKEN ? 'YES' : 'NO') : 'N/A';

    const body = `<html>
    <head>
    <title>Sammanet Server Info</title>
    <meta http-equiv="refresh" content="0; url=/page/home.md">
    <script>
    window.location.replace("/page/home.md");
    </script>
    </head>
    <body><h1>Sammanet Server</h1><ul>${
      pageList.map((p) => `<li><a href="/page/${encodeURIComponent(p)}">${escapeHtml(p)}</a></li>`).join('')
    }</ul>
    <p>Endpoints:</p>
    <ul>
      <li>View page: GET /page/<name></li>
      <li>Upload file: POST /upload (JSON: { filename, data: base64 })</li>
      <li>Download file: GET /download/<filename></li>
    </ul>
    <h2>Authentication details</h2>
    <ul>
      <li>Uploads authentication: ${UPLOAD_AUTH_ENABLED ? 'ENABLED' : 'DISABLED'}</li>
      <li>Upload token configured: ${UPLOAD_TOKEN ? 'YES' : 'NO'}</li>
      <li>Upload example:
        curl -X POST http://localhost:7742/upload -H "Content-Type: application/json" -H "Authorization: Bearer <TOKEN>" -d '{\"filename\":\"test.bin\",\"data\":\"BASE64_CONTENT\"}'
      </li>
      <li>Downloads authentication: ${downloadAuthLabel}</li>
      <li>Download token configured: ${downloadTokenLabel}</li>
      <li>Environment configuration:
        <ul>
          <li UPLOAD_ENABLED: enable/disable uploads (default true)</li>
          <li DOWNLOAD_ENABLED: enable/disable downloads (default true)</li>
          <li>UPLOAD_AUTH_ENABLED: enable/disable upload auth (default true)</li>
          <li>UPLOAD_TOKEN: token value used for uploads (default 'default-upload-token')</li>
          <li>DOWNLOAD_AUTH_ENABLED: enable/disable download auth (default false)</li>
          <li>DOWNLOAD_TOKEN: token value used for downloads (default 'default-download-token')</li>
        </ul>
      </li>
    </ul></body></html>`;
    respondHtml(200, body, nonce);
    return;
  }

  // Page rendering
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

    // Generate nonce for this page
    const nonce = crypto.randomBytes(16).toString('base64');
    const finalHtml = buildEncryptedPageHtml(name, payload, stylesHtml, snetScripts, nonce);

    // Note: CSP is applied in the final HTML
    res.writeHead(200, {
      'Content-Type': 'text/html',
      'Content-Security-Policy': `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:;`
    });
    res.end(finalHtml);
    return;
  }

  // Admin: toggle upload/download enablement
  if (url.startsWith('/admin/upload-enabled') && method === 'GET') {
    try {
      const parsed = new URL(req.url, `http://${req.headers.host}`);
      const val = parsed.searchParams.get('value');
      if (val === 'true') {
        UPLOAD_ENABLED = true;
      } else if (val === 'false') {
        UPLOAD_ENABLED = false;
      } else {
        // if missing/invalid, return current
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ enabled: UPLOAD_ENABLED }));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'invalid request' }));
    }
    return;
  }

  if (url.startsWith('/admin/status') && method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ enabled: UPLOAD_ENABLED && DOWNLOAD_ENABLED, tokenConfigured: !!UPLOAD_TOKEN }));
    return;
  }

  // Upload handling
  if (url.startsWith('/upload') && method === 'POST') {
    // Require auth for uploads (if enabled)
    if (UPLOAD_AUTH_ENABLED) {
      const auth = req.headers['authorization'];
      const token = auth && auth.startsWith('Bearer ') ? auth.slice(7) : auth;
      if (!token || token !== UPLOAD_TOKEN) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'unauthorized' }));
        return;
      }
    }

    if (!UPLOAD_ENABLED) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'uploads are disabled' }));
      return;
    }

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

        const MAX_BYTES = 10740000000; // 10 gigs
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
  // Download handling
  if (url.startsWith('/download/') && method === 'GET') {

    if (!DOWNLOAD_ENABLED) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('downloads are disabled');
      return;
    }

    // Optional authentication for downloads
    if (DOWNLOAD_AUTH_ENABLED) {
      const auth = req.headers['authorization'];
      const token = auth && auth.startsWith('Bearer ') ? auth.slice(7) : auth;
      if (!token || token !== DOWNLOAD_TOKEN) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'unauthorized' }));
        return;
      }
    }

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

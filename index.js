/*
 Minimal, robust Node.js internet server with on-the-fly page rendering (plain HTML path)
 - Pages are authored in a lightweight Markdown-like format in ./pages (e.g., hello.md).
 - Pages are rendered to HTML on the server using a Markdown library (markdown-it when available),
   then sanitized and served as complete HTML pages.
 - Custom <snet-script> and <snet-style> tags found in Markdown are preserved and injected into the final HTML as raw blocks. This is a demonstration and not production security.
 - This path renders plain HTML (no client-side decryption). Encryption-related code paths have been
   added to support server-side encryption and token-based upload/download when enabled.
*/

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

// Markdown + sanitizer (optional)
let MarkdownIt = null;
let sanitizeHtml = null;
let mdRenderer = null;
try {
  MarkdownIt = require('markdown-it');
} catch (e) {
  MarkdownIt = null;
}
try {
  sanitizeHtml = require('sanitize-html');
} catch (e) {
  sanitizeHtml = null;
}
if (MarkdownIt) {
  mdRenderer = new MarkdownIt({ html: false, linkify: true, breaks: true });
}

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

// Encryption configuration (server-side)
function deriveKeyFromString(keyString) {
  // Try to interpret as base64
  try {
    const buf = Buffer.from(keyString, 'base64');
    if (buf.length === 32) return buf;
  } catch (e) {
    // ignore
  }
  // Try hex
  try {
    const buf = Buffer.from(keyString, 'hex');
    if (buf.length === 32) return buf;
  } catch (e) {
    // ignore
  }
  // Fallback: derive from string via SHA-256
  return crypto.createHash('sha256').update(keyString || 'default-server-key').digest();
}
let ENCRYPTION_KEY = deriveKeyFromString(process.env.SERVER_ENC_KEY || 'default-server-enc-key');
if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length !== 32) {
  ENCRYPTION_KEY = crypto.createHash('sha256').update(process.env.SERVER_ENC_KEY || 'default-server-enc-key').digest();
}
function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}
ensureDir(PAGES_DIR);
ensureDir(UPLOAD_DIR);
ensureDir(UPLOAD_META_DIR);

// JSON body reader helper
function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
    });
    req.on('end', () => {
      try {
        const json = JSON.parse(data || '{}');
        resolve(json);
      } catch (e) {
        reject(e);
      }
    });
  });
}

// Basic HTML escaping (fallback)
function escapeHtml(s) {
  if (typeof s !== 'string') return '';
  return s
    .replace(/&/g, '&')
    .replace(/</g, '<')
    .replace(/>/g, '>')
    .replace(/"/g, '"')
    .replace(/'/g, '&#39;');
}

// Markdown rendering: prefer MarkdownIt if available
function mdToHtmlWithLib(md) {
  if (mdRenderer) {
    let html = mdRenderer.render(md);
    if (sanitizeHtml) {
      // sanitize output to remove disallowed tags/attributes (best-effort)
      html = sanitizeHtml(html, {
        allowedTags: sanitizeHtml.defaults?.allowedTags || [],
        allowedAttributes: sanitizeHtml.defaults?.allowedAttributes || [],
      });
    }
    return html;
  }
  // Fallback: very lightweight converter (preserve basic behavior)
  const lines = md.split(/\r?\n/);
  let html = '';
  function renderLine(line) {
    if (line.startsWith('# ')) {
      return `<h1>${escapeHtml(line.slice(2).trim())}</h1>\n`;
    } else if (line.startsWith('## ')) {
      return `<h2>${escapeHtml(line.slice(3).trim())}</h2>\n`;
    } else if (line.trim().length === 0) {
      return '\n';
    } else {
      // inline markdown links [text](url)
      let result = '';
      const regex = /\[([^\]]+)\]\(([^)]+)\)/g;
      let lastIndex = 0;
      let m;
      while ((m = regex.exec(line)) !== null) {
        const start = m.index;
        const end = regex.lastIndex;
        result += escapeHtml(line.substring(lastIndex, start));
        const text = m[1];
        const url = m[2];
        result += `<a href="${escapeHtml(url).replace(/"/g, '"')}" target="_blank" rel="noopener">${escapeHtml(text)}</a>`;
        lastIndex = end;
      }
      result += escapeHtml(line.substring(lastIndex));
      return `<p>${result}</p>\n`;
    }
  }
  for (let line of lines) {
    html += renderLine(line);
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

function buildCspMetaContent(nonce) {
  return [
    `default-src 'self'`,
    `base-uri 'self'`,
    `object-src 'none'`,
    // Scripts — allow nonce for <script> and maintain fallback for older browsers
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
    // Inline event handlers with matching hashes (optional)
    `script-src-attr 'unsafe-hashes'`,
    // Styles — allow nonce for <style>
    `style-src 'self' 'nonce-${nonce}'`,
    // Inline style attributes (optional)
    `style-src-attr 'unsafe-hashes'`,
    `img-src 'self' data:`,
    `font-src 'self' data:`
  ].join('; ');
}


// Build a plain HTML page (no encryption)
function buildPlainPageHtml(pageName, contentHtml, stylesHtml, snetScripts, nonce) {
  const scriptBlocks = (snetScripts && snetScripts.length)
    ? snetScripts.map((s) => `<script nonce="${nonce}">${s}</script>`).join('\n')
    : '';

  const html = ` 
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>${escapeHtml(pageName)}</title>
  <meta http-equiv="Content-Security-Policy" content="${buildCspMetaContent(nonce)}">
  ${stylesHtml ? `<style nonce="${nonce}">${stylesHtml}</style>` : ''}
</head>
<body>
  <div id="content">
    ${contentHtml}
  </div>
  ${scriptBlocks}
</body>
</html>`.trim();
  return html;
}

// Encryption helpers (AES-256-GCM)
function encryptBuffer(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString('base64'),
    ct: ct.toString('base64'),
    tag: tag.toString('base64')
  };
}
function decryptBuffer(enc) {
  const iv = Buffer.from(enc.iv, 'base64');
  const ct = Buffer.from(enc.ct, 'base64');
  const authTag = Buffer.from(enc.tag, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ct), decipher.final()]);
  return plaintext;
}

// Initialize with a sample page if none exist
function ensureSamplePage() {
  const files = fs.existsSync(PAGES_DIR) ? fs.readdirSync(PAGES_DIR) : [];
  const mdFiles = files.filter((f) => f.endsWith('.md'));
  if (mdFiles.length === 0) {
    const sample = [
      '# Welcome to Sammanet Server',
      '',
      'This is a sample page. It will be rendered to HTML server-side and delivered directly.',
      '',
      '<snet-style>',
      '/* Sample styles injected from <snet-style> blocks (preserved) */',
      'body { font-family: Arial, sans-serif; background: #f6f6f6; color: #333; }',
      '</snet-style>',
      '',
      '<snet-script>',
      '// Script blocks are preserved and injected as raw blocks in the final HTML.',
      '</snet-script>',
      '',
      'Enjoy exploring the plain HTML rendering path.'
    ].join('\n');
    fs.writeFileSync(path.join(PAGES_DIR, 'hello.md'), sample, 'utf8');
  }
}

// Ensure sample content initially
ensureSamplePage()

// Create the HTTP server
const server = http.createServer(async (req, res) => {
  const { method, url } = req;

  function respondHtml(status, html) {
    res.writeHead(status, {
      'Content-Type': 'text/html'
    });
    res.end(html);
  }

  // Root page: quick index
  if (url === '/' && method === 'GET') {
    let pageList = [];
    try {
      const files = fs.existsSync(PAGES_DIR) ? fs.readdirSync(PAGES_DIR) : [];
      pageList = files.filter((f) => f.endsWith('.md')).map((f) => f.replace(/\.md$/, ''));
    } catch (e) {
      pageList = [];
    }

    const nonce = crypto.randomBytes(16).toString('base64');
    const body = `<html>
<head>
  <title>Sammanet Server (Plain HTML)</title>
  <meta http-equiv="refresh" content="0; url=/page/home.md">
  <script>window.location.replace("/page/home.md");</script>
</head>
<body>
  <h1>Sammanet Server</h1>
  <ul>${pageList.map((p) => `<li><a href="/page/${encodeURIComponent(p)}">${escapeHtml(p)}</a></li>`).join('')}</ul>
  <p>Plain HTML rendering path. Page rendering at /page/<name></p>
</body>
</html>`;
    res.writeHead(200, {
      'Content-Type': 'text/html'
    });
    res.end(body);
    return;
  }

  // Upload endpoint (server-side encryption)
  if (url === '/upload' && method === 'POST') {
    // Ensure uploads are enabled
    if (!UPLOAD_ENABLED) {
      res.writeHead(403, {'Content-Type': 'application/json'});
      res.end(JSON.stringify({ ok: false, error: 'Uploads are disabled' }));
      return;
    }
    // Auth check (token-based)
    if (UPLOAD_AUTH_ENABLED) {
      const auth = req.headers['authorization'] || '';
      const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
      if (!token || token !== UPLOAD_TOKEN) {
        res.writeHead(401, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({ ok: false, error: 'Unauthorized for upload' }));
        return;
      }
    }

    try {
      const payload = await readJsonBody(req);
      const { filename, data_base64 } = payload;
      if (!filename || !data_base64) {
        res.writeHead(400, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({ ok: false, error: 'Missing filename or data_base64' }));
        return;
      }
      const plaintext = Buffer.from(data_base64, 'base64');
      const enc = encryptBuffer(plaintext);
      const encFilePath = path.join(UPLOAD_DIR, filename.endsWith('.enc.json') ? filename : filename + '.enc.json');
      fs.writeFileSync(encFilePath, JSON.stringify(enc, null, 2), 'utf8');
      // Optional meta
      const metaPath = path.join(UPLOAD_META_DIR, (filename || 'upload') + '.meta.json');
      const meta = {
        filename: path.basename(encFilePath),
        uploadedAt: Date.now(),
        size: plaintext.length,
      };
      fs.writeFileSync(metaPath, JSON.stringify(meta, null, 2), 'utf8');
      res.writeHead(200, {'Content-Type': 'application/json'});
      res.end(JSON.stringify({ ok: true, file: path.basename(encFilePath) }));
    } catch (err) {
      res.writeHead(500, {'Content-Type': 'application/json'});
      res.end(JSON.stringify({ ok: false, error: err.message }));
    }
    return;
  }

  // Download endpoint (decrypt on-the-fly)
  if (url.startsWith('/download/') && method === 'GET') {
    if (!DOWNLOAD_ENABLED) {
      res.writeHead(403, {'Content-Type': 'application/json'});
      res.end(JSON.stringify({ ok: false, error: 'Downloads are disabled' }));
      return;
    }
    // Auth for download if enabled
    if (DOWNLOAD_AUTH_ENABLED) {
      const auth = req.headers['authorization'] || '';
      const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
      if (!token || token !== DOWNLOAD_TOKEN) {
        res.writeHead(401, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({ ok: false, error: 'Unauthorized for download' }));
        return;
      }
    }

    const name = url.substring('/download/'.length);
    const encFilePath = path.join(UPLOAD_DIR, name.endsWith('.enc.json') ? name : name + '.enc.json');
    if (!fs.existsSync(encFilePath)) {
      res.writeHead(404, {'Content-Type': 'application/json'});
      res.end(JSON.stringify({ ok: false, error: 'Encrypted file not found' }));
      return;
    }
    try {
      const encRaw = fs.readFileSync(encFilePath, 'utf8');
      const enc = JSON.parse(encRaw);

      const plaintext = decryptBuffer(enc);
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${path.basename(encFilePath, '.enc.json')}"`

      });
      res.end(plaintext);
    } catch (err) {
      res.writeHead(500, {'Content-Type': 'application/json'});
      res.end(JSON.stringify({ ok: false, error: err.message }));
    }
    return;
  }

  // Plain HTML page rendering path
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
    const contentHtml = mdToHtmlWithLib(md);
    const stylesHtml = snetStyles.length > 0 ? snetStyles.join('\n') : '';

    const nonce = crypto.randomBytes(16).toString('base64');
    const finalHtml = buildPlainPageHtml(name, contentHtml, stylesHtml, snetScripts, nonce);

    res.writeHead(200, {
      'Content-Type': 'text/html',
      'Content-Security-Policy': `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:;`
    });
    res.end(finalHtml);
    return;
  }

  // Fallback: 404
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

// Start server
server.listen(PORT, () => {
  console.log('Sammanet-like server (plain HTML path) listening on http://localhost:' + PORT);
});

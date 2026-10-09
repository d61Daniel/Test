// Proxy web v2 - Node 18+ (sem dependências)
// Uso: node server.js  ->  abra http://localhost:3000
// Opcional: ACCESS_PASSWORD=minhasenha node server.js  (pede senha básica)

const http = require('http');
const crypto = require('crypto');
const dns = require('dns').promises;
const net = require('net');

const PORT = process.env.PORT || 3000;
const PASSWORD = process.env.ACCESS_PASSWORD || '';

/* ---------- Página inicial ---------- */
const HOME = `<!doctype html><html lang="pt"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebProxy – Navegue anonimamente</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
background:linear-gradient(160deg,#0b1220,#16233f 60%,#1d3260);color:#e8eefc;display:flex;flex-direction:column}
header{padding:18px 24px;font-weight:700;font-size:20px;letter-spacing:.3px}
header span{color:#5aa2ff}
main{flex:1;display:flex;align-items:center;justify-content:center;padding:20px}
.card{width:min(94vw,640px);background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);
border-radius:18px;padding:28px;backdrop-filter:blur(8px);box-shadow:0 20px 60px rgba(0,0,0,.4)}
h1{margin:0 0 6px;font-size:26px}
p.sub{margin:0 0 20px;color:#a9b8d8;font-size:15px}
.row{display:flex;gap:10px}
input[type=text]{flex:1;min-width:0;font-size:16px;padding:15px 16px;border-radius:12px;border:1px solid #2c3d63;background:#0e1830;color:#fff;outline:none}
input[type=text]:focus{border-color:#5aa2ff}
button{font-size:16px;font-weight:700;padding:0 26px;border:0;border-radius:12px;background:#3b82f6;color:#fff;cursor:pointer}
button:hover{background:#2f6fe0}
.opts{display:grid;grid-template-columns:1fr 1fr;gap:10px 16px;margin-top:18px;font-size:14px;color:#c7d3ee}
.opts label{display:flex;align-items:center;gap:8px;cursor:pointer}
footer{padding:16px;text-align:center;font-size:12px;color:#7f90b5}
@media(max-width:480px){.row{flex-direction:column}button{padding:14px}.opts{grid-template-columns:1fr}}
</style></head><body>
<header>🌐 Web<span>Proxy</span></header>
<main><form class="card" action="/go" method="get">
<h1>Navegue com privacidade</h1>
<p class="sub">Digite um endereço ou faça uma pesquisa. O site será aberto através do proxy.</p>
<input type="hidden" name="set" value="1">
<div class="row">
<input type="text" name="url" placeholder="Digite a URL ou pesquise (ex: wikipedia.org)" autocomplete="off" autofocus required>
<button type="submit">Ir</button>
</div>
<div class="opts">
<label><input type="checkbox" name="enc" value="1" checked> Criptografar URL</label>
<label><input type="checkbox" name="ac" value="1" checked> Permitir cookies</label>
<label><input type="checkbox" name="rs" value="1"> Remover scripts</label>
<label><input type="checkbox" name="ro" value="1"> Remover objetos (iframes)</label>
</div>
</form></main>
<footer>Use com responsabilidade.</footer>
</body></html>`;

/* ---------- Utilidades ---------- */
function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127);
  }
  const l = ip.toLowerCase();
  if (l.startsWith('::ffff:')) return isPrivate(l.slice(7));
  return l === '::1' || l === '::' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80');
}

async function assertPublic(hostname) {
  if (net.isIP(hostname)) {
    if (isPrivate(hostname)) throw new Error('Endereço bloqueado');
    return;
  }
  const addrs = await dns.lookup(hostname, { all: true });
  if (!addrs.length || addrs.some(a => isPrivate(a.address))) throw new Error('Endereço bloqueado');
}

const esc = s => String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  });
  return out;
}

function getOpts(cookies) {
  const s = new Set((cookies.px_opts || '').split('.').filter(Boolean));
  return { enc: s.has('enc'), ac: s.has('ac'), rs: s.has('rs'), ro: s.has('ro') };
}

// Codificação do endereço: /p/<url> (normal) ou /e/<base64> (criptografado)
const enc = (u, m) => m.enc ? '/e/' + Buffer.from(u).toString('base64url') : '/p/' + encodeURIComponent(u);

function resolve(u, base, m) {
  try {
    if (/^\s*(javascript:|data:|mailto:|tel:|blob:|#)/i.test(u)) return null;
    const a = new URL(u, base);
    if (!/^https?:$/.test(a.protocol)) return null;
    return enc(a.href, m);
  } catch { return null; }
}

/* ---------- Reescrita de conteúdo ---------- */
function rewriteCss(css, base, m) {
  return css.replace(/url\(\s*(["']?)(.*?)\1\s*\)/gi, (x, q, val) => {
    const r = resolve(val, base, m);
    return r ? `url(${q}${r}${q})` : x;
  });
}

function rewriteHtml(html, base, m) {
  html = html
    .replace(/<meta[^>]+http-equiv=["']?content-security-policy["']?[^>]*>/gi, '')
    .replace(/\s(integrity|nonce)=("[^"]*"|'[^']*')/gi, '')
    .replace(/<base[^>]*>/gi, '');

  if (m.rs) {
    html = html.replace(/<script[\s\S]*?<\/script>/gi, '')
               .replace(/\son[a-z]+=("[^"]*"|'[^']*')/gi, '');
  }
  if (m.ro) {
    html = html.replace(/<(iframe|object|embed)[\s\S]*?<\/\1>/gi, '')
               .replace(/<(iframe|object|embed)[^>]*\/?>/gi, '');
  }

  html = html
    .replace(/(\s(?:href|src|action|poster)=)(["'])(.*?)\2/gi, (x, pre, q, val) => {
      const r = resolve(val.replace(/&amp;/g, '&'), base, m);
      return r ? `${pre}${q}${r}${q}` : x;
    })
    .replace(/(\ssrcset=)(["'])(.*?)\2/gi, (x, pre, q, val) => {
      const out = val.split(',').map(part => {
        const [u, ...rest] = part.trim().split(/\s+/);
        return [resolve(u, base, m) || u, ...rest].join(' ');
      }).join(', ');
      return `${pre}${q}${out}${q}`;
    });
  html = rewriteCss(html, base, m);

  const script = m.rs ? '' : `<script>(function(){var B=${JSON.stringify(base)},E=${m.enc};
function w(u){try{u=String(u);if(u.indexOf('/p/')===0||u.indexOf('/e/')===0)return u;var a=new URL(u,B);
if(!/^https?:$/.test(a.protocol))return u;
if(E)return '/e/'+btoa(unescape(encodeURIComponent(a.href))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
return '/p/'+encodeURIComponent(a.href)}catch(e){return u}}
var f=window.fetch;window.fetch=function(i,o){if(typeof i==='string')i=w(i);return f.call(this,i,o)};
var x=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(mm,u){arguments[1]=w(u);return x.apply(this,arguments)};
})();</script>`;

  const bar = `<style>html{margin-top:46px!important}</style>
<div id="__pxbar" style="position:fixed;top:0;left:0;right:0;height:46px;z-index:2147483647;display:flex;gap:8px;align-items:center;padding:6px 10px;background:#16233f;box-shadow:0 2px 8px rgba(0,0,0,.4);font-family:system-ui,sans-serif">
<a href="/" style="color:#5aa2ff;text-decoration:none;font-weight:700;font-size:15px">🌐</a>
<form action="/go" method="get" style="flex:1;display:flex;gap:6px;margin:0">
<input name="url" value="${esc(base)}" style="flex:1;min-width:0;padding:7px 10px;border-radius:8px;border:1px solid #2c3d63;background:#0e1830;color:#fff;font-size:14px">
<button style="padding:0 14px;border:0;border-radius:8px;background:#3b82f6;color:#fff;font-weight:700;font-size:14px">Ir</button>
</form></div>`;

  if (/<head[^>]*>/i.test(html)) html = html.replace(/<head[^>]*>/i, x => x + script);
  else html = script + html;
  if (/<body[^>]*>/i.test(html)) html = html.replace(/<body[^>]*>/i, x => x + bar);
  else html = bar + html;
  return html;
}

/* ---------- Cookies (guardados no servidor, por sessão) ---------- */
const jars = new Map(); // sid -> Map(host -> Map(nome -> valor))

function jarFor(sid, host) {
  if (!jars.has(sid)) jars.set(sid, new Map());
  const j = jars.get(sid);
  if (!j.has(host)) j.set(host, new Map());
  return j.get(host);
}

const STRIP = new Set([
  'content-encoding', 'content-length', 'content-security-policy',
  'content-security-policy-report-only', 'x-frame-options', 'strict-transport-security',
  'transfer-encoding', 'connection', 'set-cookie', 'location'
]);

async function readBody(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return Buffer.concat(chunks);
}

/* ---------- Servidor ---------- */
const server = http.createServer(async (req, res) => {
  try {
    if (PASSWORD) {
      const auth = (req.headers.authorization || '').split(' ')[1] || '';
      const pass = Buffer.from(auth, 'base64').toString().split(':').slice(1).join(':');
      if (pass !== PASSWORD) {
        res.writeHead(401, { 'www-authenticate': 'Basic realm="WebProxy"' });
        return res.end('Autenticação necessária');
      }
    }

    const reqUrl = new URL(req.url, 'http://localhost');
    const cookies = parseCookies(req);
    const m = getOpts(cookies);

    if (reqUrl.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(HOME);
    }

    if (reqUrl.pathname === '/go') {
      const q = reqUrl.searchParams;
      let t = (q.get('url') || '').trim();
      if (!t) { res.writeHead(302, { location: '/' }); return res.end(); }
      const headers = { location: '' };
      const setCookies = [];
      if (q.get('set') === '1') {
        const o = ['enc', 'ac', 'rs', 'ro'].filter(k => q.get(k) === '1');
        setCookies.push(`px_opts=${o.join('.') || 'none'}; Path=/; SameSite=Lax; Max-Age=31536000`);
        m.enc = o.includes('enc'); m.ac = o.includes('ac'); m.rs = o.includes('rs'); m.ro = o.includes('ro');
      }
      if (!cookies.px_sid) {
        setCookies.push(`px_sid=${crypto.randomBytes(16).toString('hex')}; Path=/; HttpOnly; SameSite=Lax`);
      }
      if (!/^https?:\/\//i.test(t)) {
        t = /^[\w-]+(\.[\w-]+)+(:\d+)?(\/.*)?$/.test(t) ? 'https://' + t
          : 'https://duckduckgo.com/html/?q=' + encodeURIComponent(t);
      }
      headers.location = enc(t, m);
      if (setCookies.length) headers['set-cookie'] = setCookies;
      res.writeHead(302, headers);
      return res.end();
    }

    // Descobre o endereço de destino
    let target;
    if (reqUrl.pathname.startsWith('/e/')) {
      target = new URL(Buffer.from(reqUrl.pathname.slice(3), 'base64url').toString());
    } else if (reqUrl.pathname.startsWith('/p/')) {
      const raw = req.url.slice(3);
      const [first, ...rest] = raw.split('?');
      target = new URL(decodeURIComponent(first) + (rest.length ? '?' + rest.join('?') : ''));
    } else {
      res.writeHead(404); return res.end('Não encontrado');
    }
    if (!/^https?:$/.test(target.protocol)) throw new Error('Protocolo inválido');
    await assertPublic(target.hostname);

    const sid = cookies.px_sid || crypto.randomBytes(16).toString('hex');
    const headers = {
      'user-agent': req.headers['user-agent'] || 'Mozilla/5.0',
      'accept': req.headers['accept'] || '*/*',
      'accept-language': req.headers['accept-language'] || 'pt-BR,pt;q=0.9,en;q=0.8',
    };
    if (req.headers['content-type']) headers['content-type'] = req.headers['content-type'];
    if (req.headers['range']) headers['range'] = req.headers['range'];
    if (m.ac) {
      const jar = jarFor(sid, target.hostname);
      if (jar.size) headers['cookie'] = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
    }

    const hasBody = !['GET', 'HEAD'].includes(req.method);
    const upstream = await fetch(target.href, {
      method: req.method,
      headers,
      body: hasBody ? await readBody(req) : undefined,
      redirect: 'manual',
    });

    const out = {};
    upstream.headers.forEach((v, k) => { if (!STRIP.has(k)) out[k] = v; });
    const outCookies = [];
    if (!cookies.px_sid) outCookies.push(`px_sid=${sid}; Path=/; HttpOnly; SameSite=Lax`);
    if (m.ac) {
      const sc = typeof upstream.headers.getSetCookie === 'function' ? upstream.headers.getSetCookie() : [];
      const jar = jarFor(sid, target.hostname);
      for (const c of sc) {
        const [pair] = c.split(';');
        const i = pair.indexOf('=');
        if (i > 0) {
          const name = pair.slice(0, i).trim(), val = pair.slice(i + 1).trim();
          if (/max-age=0|expires=thu, 01 jan 1970/i.test(c) || val === '') jar.delete(name);
          else jar.set(name, val);
        }
      }
    }
    if (outCookies.length) out['set-cookie'] = outCookies;

    const loc = upstream.headers.get('location');
    if (upstream.status >= 300 && upstream.status < 400 && loc) {
      out.location = resolve(loc, target.href, m) || loc;
      res.writeHead(upstream.status, out);
      return res.end();
    }

    const type = upstream.headers.get('content-type') || '';
    if (type.includes('text/html')) {
      const body = rewriteHtml(await upstream.text(), target.href, m);
      res.writeHead(upstream.status, { ...out, 'content-type': type });
      return res.end(body);
    }
    if (type.includes('text/css')) {
      const body = rewriteCss(await upstream.text(), target.href, m);
      res.writeHead(upstream.status, { ...out, 'content-type': type });
      return res.end(body);
    }

    const buf = Buffer.from(await upstream.arrayBuffer());
    res.writeHead(upstream.status, { ...out, 'content-length': buf.length });
    res.end(buf);
  } catch (e) {
    res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('Erro no proxy: ' + e.message);
  }
});

server.listen(PORT, () => console.log(`Proxy rodando em http://localhost:${PORT}`));

/**
 * Scut — passive domain security checker
 * Cloudflare Worker (edge). 100% passive & legal: only public DNS and a single
 * browser-level HTTPS GET. No port scanning, no payloads, no intrusion.
 *
 * Routes:
 *   GET /               -> UI
 *   GET /api/scut?domain=example.com -> JSON report
 *
 * Author: Morariu Andrei Raul — https://morariuandreiraul.com/scut
 * License: MIT
 */

async function doh(name, type) {
  try {
    const r = await fetch(
      "https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(name) + "&type=" + type,
      { headers: { accept: "application/dns-json" }, cf: { cacheTtl: 300 } }
    );
    if (!r.ok) return { ok: false, ad: false, answers: [] };
    const j = await r.json();
    return { ok: true, ad: j.AD === true, status: j.Status, answers: Array.isArray(j.Answer) ? j.Answer : [] };
  } catch (e) {
    return { ok: false, ad: false, answers: [], error: true };
  }
}

function txtValues(ans) {
  return ans
    .map((a) => (a.data || "").replace(/^"|"$/g, "").replace(/" "/g, ""))
    .filter(Boolean);
}

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "max-age=60", "access-control-allow-origin": "*" },
  });
}

async function handleScut(url, ctx) {
  let d = (url.searchParams.get("domain") || "").trim().toLowerCase();
  d = d.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/:.*$/, "").replace(/\.$/, "");
  const valid = /^(?=.{1,253}$)([a-z0-9](-?[a-z0-9]){0,62}\.)+[a-z]{2,63}$/.test(d);
  const blocked =
    /(^|\.)(local|internal|lan|test|localhost|home|corp|intranet)$/.test(d) ||
    /^\d{1,3}(\.\d{1,3}){3}$/.test(d);
  if (!valid || blocked) {
    return json({ ok: false, error: "Invalid domain. Enter a public domain, e.g. example.com" }, 400);
  }

  const cache = caches.default;
  const key = new Request("https://scut.local/api/scut?domain=" + d);
  const hit = await cache.match(key);
  if (hit) return hit;

  const selectors = ["google", "selector1", "selector2", "default", "k1", "dkim", "mail", "s1", "s2", "smtp", "mandrill"];
  const results = await Promise.all([
    doh(d, "TXT"),
    doh("_dmarc." + d, "TXT"),
    doh(d, "MX"),
    doh(d, "DNSKEY"),
    doh(d, "CAA"),
    doh("_mta-sts." + d, "TXT"),
    ...selectors.map((s) => doh(s + "._domainkey." + d, "TXT")),
  ]);
  const [txt, dmarc, mx, dnskeyQ, caa, mtaSts] = results;
  const dkimR = results.slice(6);

  const checks = [];
  const add = (id, label, status, detail) => checks.push({ id, label, status, detail });

  const spf = txtValues(txt.answers).find((t) => /v=spf1/i.test(t));
  if (spf) {
    const strict = /[-~]all\s*$/.test(spf);
    add("spf", "SPF (email anti-spoofing)", strict ? "pass" : "warn",
      strict ? "Present and restrictive." : "Present, but does not end with -all / ~all.");
  } else add("spf", "SPF (email anti-spoofing)", "fail", "Missing. Anyone can send email as this domain.");

  const dm = txtValues(dmarc.answers).find((t) => /v=DMARC1/i.test(t));
  if (dm) {
    const p = (dm.match(/p=([a-z]+)/i) || [])[1] || "none";
    add("dmarc", "DMARC", p === "reject" || p === "quarantine" ? "pass" : "warn",
      "Present, policy p=" + p + (p === "none" ? " (monitor only)." : "."));
  } else add("dmarc", "DMARC", "fail", "Missing. No protection against email spoofing.");

  const dkim = dkimR
    .map((r, i) => ({ sel: selectors[i], t: txtValues(r.answers).find((x) => /v=DKIM1|k=rsa|p=[A-Za-z0-9]/.test(x)) }))
    .filter((x) => x.t);
  if (dkim.length) add("dkim", "DKIM (email signature)", "pass", "Found on: " + dkim.map((x) => x.sel).join(", ") + ".");
  else add("dkim", "DKIM (email signature)", "info", "Not found on common selectors (a custom one may exist).");

  if (mx.answers.length) add("mx", "MX (mail servers)", "info", mx.answers.length + " mail server(s) configured.");
  else add("mx", "MX (mail servers)", "info", "No MX — domain does not receive email.");

  const dnssec = dnskeyQ.answers.length > 0 || txt.ad === true;
  add("dnssec", "DNSSEC", dnssec ? "pass" : "warn",
    dnssec ? "Active — DNS responses are signed." : "Inactive — DNS is easier to spoof.");

  if (caa.answers.length) add("caa", "CAA (certificate control)", "pass", "Present — restricts who can issue TLS certificates.");
  else add("caa", "CAA (certificate control)", "warn", "Missing — any CA can issue a certificate for this domain.");

  if (txtValues(mtaSts.answers).some((t) => /v=STSv1/i.test(t))) add("mtasts", "MTA-STS (encrypted email in transit)", "pass", "Present.");

  let headScore = 0;
  const headTotal = 6;
  let httpsOk = false;
  try {
    const ctrl = new AbortController();
    const to = setTimeout(() => ctrl.abort(), 6000);
    const resp = await fetch("https://" + d + "/", {
      method: "GET", redirect: "follow", signal: ctrl.signal, cf: { cacheTtl: 60 },
      headers: { "user-agent": "Scut security checker (+https://morariuandreiraul.com/scut)" },
    });
    clearTimeout(to);
    httpsOk = true;
    const h = resp.headers;
    const csp = h.get("content-security-policy") || "";
    const want = [
      ["strict-transport-security", "HSTS (forces HTTPS)", h.get("strict-transport-security") != null],
      ["content-security-policy", "Content-Security-Policy", csp !== ""],
      ["x-content-type-options", "X-Content-Type-Options (nosniff)", h.get("x-content-type-options") != null],
      ["x-frame-options", "Anti-clickjacking (X-Frame-Options)", h.get("x-frame-options") != null || /frame-ancestors/i.test(csp)],
      ["referrer-policy", "Referrer-Policy", h.get("referrer-policy") != null],
      ["permissions-policy", "Permissions-Policy", h.get("permissions-policy") != null],
    ];
    for (const [id, label, present] of want) {
      if (present) headScore++;
      add("hdr_" + id, label, present ? "pass" : "fail", present ? "Present." : "Missing.");
    }
  } catch (e) {
    add("https", "HTTPS", "warn", "Domain did not respond over HTTPS (email-only, or currently unavailable).");
  }

  let score = 0;
  const has = (id, st) => checks.some((c) => c.id === id && c.status === st);
  if (has("spf", "pass")) score += 14; else if (has("spf", "warn")) score += 7;
  if (has("dmarc", "pass")) score += 16; else if (has("dmarc", "warn")) score += 8;
  if (has("dkim", "pass")) score += 8;
  if (has("dnssec", "pass")) score += 12;
  if (has("caa", "pass")) score += 6;
  if (httpsOk) score += Math.round((headScore / headTotal) * 44);
  score = Math.max(0, Math.min(100, Math.round(score)));
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";

  const body = JSON.stringify({ ok: true, domain: d, score, grade, httpsOk, checks, ts: Date.now() });
  const out = new Response(body, {
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "max-age=300", "access-control-allow-origin": "*" },
  });
  ctx.waitUntil(cache.put(key, out.clone()));
  return out;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/api/scut") return handleScut(url, ctx);
    return new Response(UI, { headers: { "content-type": "text/html; charset=utf-8" } });
  },
};

const UI = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Scut — Domain Security Checker</title>
<style>
:root{--bg:#0a0a0c;--card:#141418;--line:#26262d;--fg:#e9e9ec;--mut:#9a9aa2;--red:#EC0000;--green:#38d39f;--amber:#f5a623}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font-family:ui-monospace,"DejaVu Sans Mono",monospace;line-height:1.5}
.wrap{max-width:760px;margin:0 auto;padding:40px 18px 80px}
h1{font-size:30px;margin:0 0 6px}h1 b{color:var(--red)}
.sub{color:var(--mut);margin:0 0 26px}
form{display:flex;gap:10px;flex-wrap:wrap}
input{flex:1;min-width:220px;background:var(--card);border:1px solid var(--line);color:var(--fg);padding:14px 16px;border-radius:10px;font:inherit;font-size:16px}
button{background:var(--red);color:#fff;border:0;padding:14px 22px;border-radius:10px;font:inherit;font-weight:700;cursor:pointer}
button:disabled{opacity:.5}
.ex{margin:10px 0 0;color:var(--mut);font-size:13px}.ex a{color:var(--mut)}
#out{margin-top:30px}
.score{display:flex;align-items:center;gap:20px;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:22px;margin-bottom:20px}
.ring{width:96px;height:96px;border-radius:50%;display:grid;place-items:center;flex:none;font-size:30px;font-weight:700}
.row{display:flex;gap:12px;padding:12px 0;border-bottom:1px solid var(--line)}
.row:last-child{border:0}
.dot{flex:none;width:10px;height:10px;border-radius:50%;margin-top:7px}
.pass .dot{background:var(--green)}.warn .dot{background:var(--amber)}.fail .dot{background:var(--red)}.info .dot{background:var(--mut)}
.lbl{font-weight:700}.det{color:var(--mut);font-size:14px}
.note{color:var(--mut);font-size:12px;margin-top:30px;border-top:1px solid var(--line);padding-top:16px}
</style></head><body><div class="wrap">
<h1>🛡️ Scut<b>.</b></h1>
<p class="sub">Passive domain security checker — email, DNS & HTTP headers. Public data only.</p>
<form id="f"><input id="d" placeholder="example.com" autocomplete="off" autocapitalize="off" spellcheck="false"><button id="b">Scan</button></form>
<p class="ex">Try: <a href="#" data-d="github.com">github.com</a> · <a href="#" data-d="cloudflare.com">cloudflare.com</a></p>
<div id="out"></div>
<p class="note">Scut performs no active scanning: it reads public DNS records and makes a single browser-level HTTPS request, exactly like visiting the site. No ports, payloads or intrusion. GDPR-clean.</p>
</div><script>
var col={A:"#38d39f",B:"#8ed34f",C:"#f5a623",D:"#f5781a",F:"#EC0000"};
function run(dom){
  var out=document.getElementById('out'),b=document.getElementById('b');
  out.innerHTML='<p style="color:#9a9aa2">Scanning '+dom+'…</p>';b.disabled=true;
  fetch('/api/scut?domain='+encodeURIComponent(dom)).then(function(r){return r.json()}).then(function(j){
    b.disabled=false;
    if(!j.ok){out.innerHTML='<p style="color:#EC0000">'+(j.error||'Error')+'</p>';return}
    var c=col[j.grade]||'#9a9aa2';
    var h='<div class="score"><div class="ring" style="color:'+c+';background:conic-gradient('+c+' '+(j.score*3.6)+'deg,#26262d 0)"><div style="width:76px;height:76px;border-radius:50%;background:#141418;display:grid;place-items:center">'+j.grade+'</div></div><div><div style="font-size:30px;font-weight:700">'+j.score+'<span style="color:#9a9aa2;font-size:18px">/100</span></div><div style="color:#9a9aa2">'+j.domain+'</div></div></div>';
    j.checks.forEach(function(x){h+='<div class="row '+x.status+'"><div class="dot"></div><div><div class="lbl">'+x.label+'</div><div class="det">'+x.detail+'</div></div></div>'});
    out.innerHTML=h;
  }).catch(function(){b.disabled=false;out.innerHTML='<p style="color:#EC0000">Network error.</p>'});
}
document.getElementById('f').addEventListener('submit',function(e){e.preventDefault();var d=document.getElementById('d').value.trim();if(d)run(d)});
document.querySelectorAll('.ex a').forEach(function(a){a.addEventListener('click',function(e){e.preventDefault();document.getElementById('d').value=a.dataset.d;run(a.dataset.d)})});
</script></body></html>`;

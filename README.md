# 🛡️ Scut — Passive Domain Security Checker

**Live demo → [morariuandreiraul.com/scut](https://morariuandreiraul.com/scut)**

Scut ("shield" in Romanian) grades the security posture of any public domain in
seconds — email authentication, DNS hardening and HTTP security headers — and
returns a single 0–100 score with an A–F grade and a per-check breakdown.

It runs entirely at the edge on a single Cloudflare Worker (no servers, no
database) and is **100% passive and legal**: it reads public DNS records and
makes one browser-level HTTPS request, exactly like visiting the site. No port
scanning, no payloads, no intrusion.

---

## What it checks

| Area | Checks |
|------|--------|
| **Email anti-spoofing** | SPF (with `-all`/`~all` strictness), DMARC (policy `p=`), DKIM (11 common selectors) |
| **DNS hardening** | DNSSEC (DNSKEY / AD flag), CAA, MTA-STS, MX |
| **HTTP headers** | HSTS, Content-Security-Policy, X-Content-Type-Options, anti-clickjacking, Referrer-Policy, Permissions-Policy |

Each check returns `pass` / `warn` / `fail` / `info` with a plain-language
explanation, and the overall score is weighted toward the controls that matter
most (email spoofing protection and transport security).

## How it works

```
Browser ──► Cloudflare Worker ──► DNS-over-HTTPS (Cloudflare 1.1.1.1)
                              └──► one HTTPS GET to the target (headers only)
```

- **DNS** is queried over DoH (`cloudflare-dns.com/dns-query`, JSON) — all record
  lookups run in parallel.
- **Headers** come from a single `fetch()` with a 6s timeout, following
  redirects, reading response headers only.
- Results are cached at the edge (`caches.default`) for 5 minutes per domain.

Nothing about the target is stored; every scan is stateless.

## Run it yourself

```bash
npm i -g wrangler
git clone https://github.com/morariuraulandrei-commits/scut.git && cd scut
wrangler deploy
```

That's it — the Worker serves both the UI (`/`) and the JSON API
(`/api/scut?domain=example.com`). No build step, no dependencies.

### API

```
GET /api/scut?domain=example.com
```

```json
{
  "ok": true,
  "domain": "example.com",
  "score": 82,
  "grade": "B",
  "httpsOk": true,
  "checks": [
    { "id": "spf", "label": "SPF (email anti-spoofing)", "status": "pass", "detail": "Present and restrictive." }
  ]
}
```

`access-control-allow-origin: *` is set, so the API can be called from any
front-end.

## Legal & ethics

Scut only accesses information a domain publishes to the world: its DNS zone and
the HTTP response of its own homepage. This is the same data your browser reads
on every visit and is explicitly **not** a computer-intrusion technique under
Romanian Criminal Code art. 360–366 or EU Directive 2013/40/EU. No personal data
is collected or stored (GDPR-clean). Private / internal / IP targets are rejected.

## Tech

Cloudflare Workers · DNS-over-HTTPS · zero dependencies · vanilla JS UI

## License

MIT © Morariu Andrei Raul

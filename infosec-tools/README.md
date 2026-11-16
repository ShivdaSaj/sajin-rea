# Infosec Tools

One site that combines four self-hosted toolkits as tabs. The tool catalog was built by analysing each site with [REA](https://github.com/morluto/rea). Tools are being rebuilt natively in phases; any tool not rebuilt yet links to the original instance.

| Tab | Source site | Tools | Native now |
|---|---|---|---|
| **IT Utilities** | ittools.sajinshivdas.online (IT-Tools) | 86 | 47 |
| **Cipher Lab** | cyberchef.sajinshivdas.online (CyberChef) | 504 | 109 |
| **Web Recon** | webcheck.sajinshivdas.online (Web-Check) | 39 | 32 |
| **Network Toolkit** | networking-toolbox.sajinshivdas.online | 160 | 66 |
| **Total** | | **789** | **254** |

- **Native** tools run entirely in the browser: encoders, hashes, AES/JWT/TOTP, subnet and CIDR math, IPv6, text and data converters. Cipher Lab also has a CyberChef-style **recipe builder** that chains operations.
- **Live** tools run on the server: DNS, propagation, SPF/DMARC/DKIM, DNSSEC, TLS chain and versions, security headers, HSTS, cookies, redirects, RDAP/WHOIS, DNSBL, CT-log subdomains, open ports and more. Every outbound request goes through an SSRF guard (`lib/netsafe.mjs`). The guard refuses private, loopback, link-local, CGNAT, metadata and reserved addresses, and connects only to the IP it checked.
- **Link** tools aren't rebuilt yet. They open the matching tool on your existing instance.

## Admin panel

`/admin` signs in with `ADMIN_PASSWORD`. From there you can:
- rename, describe, reorder, hide, add or delete tabs
- add, edit, hide or delete tools
- point a tool at any native or live implementation, with preset arguments
- set a tool's link to the original
- mark tools as featured on the landing page
- import and export the catalog as JSON

Every save takes a backup first (the latest 50 are kept). You can restore any backup, or reset to the REA-built seed. The catalog lives in the `/data` volume, so it survives redeploys.

Security: the session cookie is HttpOnly, Secure and SameSite=Strict. Writes need a CSRF header. Logins are rate-limited (5 failures locks that IP out for 15 minutes). Pages are served with a strict CSP and security headers.

## Deploy with Hostinger Docker Manager (current production)

The VPS project `infosec-tools` runs `docker-compose.hostinger.yml`. It pulls the stock `node:24-alpine` image, and at start-up fetches this app from the public repository at the commit pinned in `APP_REF`, then runs it behind the existing Traefik (`websecure` entrypoint, `letsencrypt` resolver). `ADMIN_PASSWORD` is a project environment variable in hPanel → VPS → Docker Manager. To deploy new code, set `APP_REF` to the new commit and redeploy the project from Docker Manager. GitHub Actions also runs the tests and publishes `ghcr.io/shivdasaj/infosec-tools` on every push.

## Deploy manually (any Docker + Traefik host)

```bash
git clone <this repo> && cd sajin-rea/infosec-tools
./deploy.sh
```

`deploy.sh` finds your running Traefik container. It reads Traefik's network, HTTPS entrypoint and certificate resolver, then writes `.env` with a generated admin password, which it prints once. Then it runs `docker compose up -d --build`. Before you run it, the DNS **A record** for `infosectools.sajinshivdas.online` must point at the server. To update, run `git pull && ./deploy.sh`.

## Develop

```bash
ADMIN_PASSWORD=dev COOKIE_SECURE=false node server.mjs     # http://localhost:8080
node --test test/*.test.mjs                                # known-answer tests for the native ops
node scripts/build-catalog.mjs                             # rebuild seed/catalog.json after editing the op mapping
```

There are no npm dependencies; Node.js 22+ is all you need. To rebuild another tool natively:
1. Add an op to `public/ops/*.js`, or to `lib/server-ops.mjs` for server checks.
2. Map the source tool to it in `scripts/build-catalog.mjs`.
3. Rebuild the seed catalog, or link the tool to the op from the admin panel.

## Where the catalog comes from

`seed/provenance.json` records how the catalog was built:
- The four sites were mirrored over HTTPS.
- REA 6.9.0 `analyze-javascript-application` ran statically on each mirror. No target code was executed.
- Each site's tool list was read from its own registry in the same bundles: IT-Tools' tool definitions, CyberChef's categories and operation config, Web-Check's job registry, and Networking Toolbox's navigation data.

REA completed on CyberChef, Web-Check and Networking Toolbox. On IT-Tools it hit its 300-second per-bundle limit, so it produced only partial Evidence. IT-Tools' route registry was still read in full.

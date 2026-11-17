# Infosec Tools

A portal of four toolkits, styled like [Forensics Atlas](https://forensics.sajinshivdas.online/). Each toolkit was rebuilt natively from a self-hosted site after static analysis with [REA](https://github.com/morluto/rea). Only rebuilt tools are published: the 89 tools that couldn't be rebuilt without large external libraries, datasets or API keys are excluded.

| Toolkit | Rebuilt from | Tools | Categories |
|---|---|---|---|
| **IT Toolkit** | ittools.sajinshivdas.online (IT-Tools) | 76 | 10 |
| **CyberChef Toolkit** | cyberchef.sajinshivdas.online (CyberChef) | 430 | 16 |
| **Web Toolkit** | webcheck.sajinshivdas.online (Web-Check) | 35 | 7 |
| **Network Toolkit** | networking-toolbox.sajinshivdas.online | 159 | 7 |
| **Total** | | **700** | **40** |

The site has a home page (hero, toolkit cards, a how-it-works stepper, category cards for each toolkit, recommended tools and REA provenance), a **Toolkits** page with a tab for each toolkit, an **Explore** page with a toolkit and category sidebar, a **recipe builder** for the CyberChef Toolkit, a **Saved** shortlist, and a Ctrl K search palette. Clicking a tool opens it in a side drawer where it runs straight away; each tool also has a full page.

- **Browser** tools (621) run entirely in the browser: encoders and data formats, hashes and checksums (SHA-2/3, BLAKE2/3, RIPEMD, CRC family, SSDEEP…), ciphers (AES, DES/3DES, Blowfish, ChaCha20, Salsa20, RC4, Rabbit, classical), KDFs and password hashes (PBKDF2, HKDF, scrypt, bcrypt, Argon2), X.509/CSR/CRL and ASN.1 parsing, RSA/ECDSA, YAML/TOML/XML/MessagePack/CBOR conversion, compression and archives, forensics (file type, embedded files, ELF, EXIF, plist), QR codes and image tools, packet parsers with JA3/JA4/HASSH fingerprints, subnet/CIDR/IPv6 maths, DNS and DNSSEC record builders, DHCP option encoders and reference sheets. File and image tools accept a dropped file or pasted hex/Base64 and offer the result as a download.
- **Live** checks (79) run on the server: DNS, propagation, resolver timing, SPF/DMARC/DKIM and SPF flattening, DNSSEC, TLS chain/versions/OCSP stapling, mail STARTTLS, security headers, CORS, compression, HSTS, cookies, redirects, RDAP/WHOIS/ASN, BGP prefix and RPKI, DNSBL, CT-log subdomains, IPv6 reachability, open ports, Tranco rank, carbon footprint, PageSpeed quality, zone-transfer (AXFR) testing, iterative DNS trace and safe HTTP requests (GET/HEAD/OPTIONS only). Every outbound request goes through an SSRF guard (`lib/netsafe.mjs`). The guard refuses private, loopback, link-local, CGNAT, metadata and reserved addresses, and connects only to the IP it checked.

## Admin panel

`/admin` signs in with `ADMIN_PASSWORD` and uses the same design as the site. From there you can:
- **Site settings**: title, brand, home page hero text (with a live preview), footer text, the default colour theme (dark, light, ember, terminal, ocean, paper, contrast) and accent colours
- **Toolkits**: add, rename, describe, recolour, reorder, hide or delete toolkits
- **Categories** in each toolkit: add, rename (the tools follow), describe, pick an icon, reorder, move all tools to another category, delete empty ones
- **Tools** in each toolkit: add, edit, preview, move to another toolkit, hide, feature on the home page or delete. Each tool gets a browser or live implementation (searchable picker), preset options, a sub-category, keywords and an optional link
- **Backups & import**: restore any backup, export or import the catalog as JSON, reset to the shipped seed

Changes are collected locally and go live when you press **Save** (or Ctrl+S).

When a new release ships a newer seed catalog, the server upgrades the stored catalog on start-up: new tools are added and tools gain new implementations, while admin renames, hidden tools, deletions and category edits are kept. A backup is written first. A catalog from before the toolkit restructure (v1: IT Utilities, Cipher Lab, Web Recon, Network Toolkit) is migrated once to the four toolkits, with link-only tools removed and admin renames kept.

Every save takes a backup first (the latest 50 are kept). You can restore any backup, or reset to the REA-built seed. The catalog lives in the `/data` volume, so it survives redeploys.

Security: the session cookie is HttpOnly, Secure and SameSite=Strict. Writes need a CSRF header. Logins are rate-limited (5 failures locks that IP out for 15 minutes). Pages are served with a strict CSP and security headers.

## Deploy with Hostinger Docker Manager (current production)

The VPS project `infosec-tools` runs `docker-compose.hostinger.yml`. It pulls the stock `node:24-alpine` image, and at start-up fetches this app from the public repository at the commit pinned in `APP_REF`, then runs it behind the existing Traefik (`websecure` entrypoint, `letsencrypt` resolver). `ADMIN_PASSWORD` is a project environment variable in hPanel → VPS → Docker Manager. To deploy new code, set the `APP_REF` project environment variable to the new commit (it overrides the default in the compose file) and redeploy the project from Docker Manager. GitHub Actions also runs the tests and publishes `ghcr.io/shivdasaj/infosec-tools` on every push.

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
2. Map the source tool to it in `scripts/build-catalog.mjs` (category cards and featured tools are defined there too).
3. Rebuild the seed catalog, or add the tool from the admin panel.

## Where the catalog comes from

`seed/provenance.json` records how the catalog was built:
- The four sites were mirrored over HTTPS.
- REA 6.9.0 `analyze-javascript-application` ran statically on each mirror. No target code was executed.
- Each site's tool list was read from its own registry in the same bundles: IT-Tools' tool definitions, CyberChef's categories and operation config, Web-Check's job registry, and Networking Toolbox's navigation data.

Fonts (Inter and JetBrains Mono, SIL OFL 1.1) are self-hosted in `public/fonts` because the content security policy only allows same-origin resources. The base styles in `public/atlas.css` come from Forensics Atlas so the two sites share one look.

REA completed on CyberChef, Web-Check and Networking Toolbox. On IT-Tools it hit its 300-second per-bundle limit, so it produced only partial Evidence. IT-Tools' route registry was still read in full.

# Infosec Tools

One site that combines four self-hosted toolkits as tabs. The tool catalog was built by analysing each site with [REA](https://github.com/morluto/rea). Tools are being rebuilt natively in phases; any tool not rebuilt yet links to the original instance.

| Tab | Source site | Tools | Native now |
|---|---|---|---|
| **IT Utilities** | ittools.sajinshivdas.online (IT-Tools) | 86 | 76 |
| **Cipher Lab** | cyberchef.sajinshivdas.online (CyberChef) | 504 | 430 |
| **Web Recon** | webcheck.sajinshivdas.online (Web-Check) | 39 | 35 |
| **Network Toolkit** | networking-toolbox.sajinshivdas.online | 160 | 159 |
| **Total** | | **789** | **700** |

- **Native** tools run entirely in the browser: encoders and data formats, hashes and checksums (SHA-2/3, BLAKE2, RIPEMD, CRC family…), ciphers (AES, ChaCha20, Salsa20, RC4, TEA, classical), KDFs (PBKDF2, HKDF, scrypt), X.509/CSR/CRL and ASN.1 parsing, RSA/ECDSA signing and encryption, YAML/TOML/XML/MessagePack/CBOR conversion, compression, subnet/CIDR/IPv6 math, DNS and DNSSEC record builders, DHCP option encoders and network reference sheets. Phase 3 added block ciphers (DES/3DES, Blowfish, RC6, PRESENT, Rabbit), password hashing (bcrypt, Argon2, LM) and more digests (SHA-0, SM3, Whirlpool, BLAKE3, SSDEEP), a QR encoder, canvas image tools and charts, forensics (file type, embedded files, ELF, EXIF, plist, ID3), archives (Zip, Tar, LZ4, LZNT1, XPRESS), packet parsers with JA3/JA4/HASSH fingerprints, and more formats and utilities. File and image tools accept a dropped file or pasted hex/base64 and offer the result as a download. Cipher Lab also has a CyberChef-style **recipe builder** that chains operations.
- **Live** tools run on the server: DNS, propagation, resolver timing, SPF/DMARC/DKIM and SPF flattening, DNSSEC, TLS chain/versions/OCSP stapling, mail STARTTLS, security headers, CORS, compression, HSTS, cookies, redirects, RDAP/WHOIS/ASN, BGP prefix and RPKI, DNSBL, CT-log subdomains, IPv6 reachability, open ports, Tranco rank, carbon footprint, PageSpeed quality, DNS zone-transfer (AXFR) testing, iterative DNS trace and safe HTTP requests (GET/HEAD/OPTIONS only). Every outbound request goes through an SSRF guard (`lib/netsafe.mjs`). The guard refuses private, loopback, link-local, CGNAT, metadata and reserved addresses, and connects only to the IP it checked.
- **Link** tools aren't rebuilt yet. They open the matching tool on your existing instance.

## Admin panel

`/admin` signs in with `ADMIN_PASSWORD`. From there you can:
- rename, describe, reorder, hide, add or delete tabs
- add, edit, hide or delete tools
- point a tool at any native or live implementation, with preset arguments
- set a tool's link to the original
- mark tools as featured on the landing page
- import and export the catalog as JSON

When a new release ships a newer seed catalog, the server upgrades the stored catalog on start-up: tools gain new native implementations and new tools are added, while admin renames, hidden tools, deletions and deliberately unlinked tools are kept. A backup is written first.

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

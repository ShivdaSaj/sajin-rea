// Build seed/catalog.json from the four REA-derived inventories plus the native op mapping.
// Run: node scripts/build-catalog.mjs
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { registry } from "../public/ops/index.js";
import { serverOps } from "../lib/server-ops.mjs";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const seed = (f) => JSON.parse(fs.readFileSync(path.join(root, "seed", f), "utf8"));

// source tool id -> native op ("op" or "op?arg=value&..." to preset arguments; "server:" prefix = server-side op)
const MAP = {
  ittools: {
    // phase 3
    bcrypt: "bcrypt-hash", "bip39-generator": "bip39-generate", "base64-file-converter": "base64-file", "qrcode-generator": "qr-generate", "wifi-qrcode-generator": "wifi-qr",
    "git-memo": "git-memo", "regex-memo": "regex-memo",
    // phase 2
    "yaml-to-json-converter": "yaml-to-json", "yaml-to-toml": "yaml-to-toml", "json-to-toml": "json-to-toml", "toml-to-json": "toml-to-json", "toml-to-yaml": "toml-to-yaml",
    "xml-to-json": "xml-to-json", "yaml-prettify": "yaml-prettify", "http-status-codes": "http-status", "mime-types": "mime-types", "json-diff": "json-diff", "safelink-decoder": "safelink-decode",
    "email-normalizer": "email-normalize", "random-port-generator": "random-port", "crontab-generator": "cron-describe", "sql-prettify": "sql-format",
    "docker-run-to-docker-compose-converter": "docker-run-to-compose", "math-evaluator": "math-eval", "eta-calculator": "eta-calc", "iban-validator-and-parser": "iban-validate",
    "svg-placeholder-generator": "svg-placeholder", "og-meta-generator": "og-meta", "device-information": "device-info",
    "token-generator": "token", "hash-text": "hash-all", "uuid-generator": "uuid", "ulid-generator": "ulid", "encryption": "aes-encrypt", "hmac-generator": "hmac",
    "rsa-key-pair-generator": "rsa-keygen", "password-strength-analyser": "password-strength", "date-converter": "unix-timestamp", "base-converter": "base-convert",
    "roman-numeral-converter": "roman", "base64-string-converter": "base64-encode", "color-converter": "color-convert", "case-converter": "case-convert", "text-to-nato-alphabet": "nato-alphabet",
    "text-to-binary": "binary-encode", "text-to-unicode": "unicode-escape", "json-to-yaml-converter": "json-to-yaml", "list-converter": "list-convert", "json-to-xml": "json-to-xml",
    "markdown-to-html": "markdown-to-html", "url-encoder": "url-encode", "html-entities": "html-encode", "url-parser": "url-parse", "basic-auth-generator": "basic-auth", "otp-generator": "otp",
    "jwt-parser": "jwt-decode", "slugify-string": "slugify", "user-agent-parser": "user-agent", "json-prettify": "json-format", "json-minify": "json-minify", "json-to-csv": "json-to-csv",
    "chmod-calculator": "chmod", "xml-formatter": "xml-format", "regex-tester": "regex-tester", "ipv4-subnet-calculator": "subnet-calc", "ipv4-address-converter": "ip-convert",
    "ipv4-range-expander": "range-to-cidr", "mac-address-generator": "mac-generate", "ipv6-ula-generator": "ipv6-ula", "percentage-calculator": "percentage", "temperature-converter": "temperature",
    "lorem-ipsum-generator": "lorem-ipsum", "text-statistics": "text-stats", "string-obfuscator": "string-obfuscate", "text-diff": "text-diff", "numeronym-generator": "numeronym",
  },
  "networking-toolbox": {
    // phase 3
    "diagnostics--dns--axfr-tester": "server:axfr-test", "diagnostics--dns--trace": "server:dns-trace",
    // phase 2
    "ip-address-convertor--distance": "ip-distance", "ip-address-convertor--nth-ip": "nth-ip", "ip-address-convertor--regex": "ip-regex", "ip-address-convertor--notation--zone-id": "ipv6-zone-id",
    "ip-address-convertor--ipv6--solicited-node": "solicited-node", "ip-address-convertor--ipv6--teredo": "teredo-decode", "ip-address-convertor--ipv6--nat64": "nat64", "ip-address-convertor--families--ipv6-to-ipv4": "ipv6-to-ipv4",
    "dns--reverse--zone-generator": "reverse-zone-gen", "dns--reverse--reverse-zones": "reverse-zones", "dns--reverse--ptr-sweep-planner": "ptr-sweep", "dns--generators--a-aaaa-bulk": "a-aaaa-bulk", "dns--generators--cname-builder": "cname-builder",
    "dns--generators--mx-planner": "mx-planner", "dns--generators--srv-builder": "srv-builder", "dns--generators--txt-escape": "txt-escape", "dns--generators--spf-builder": "spf-builder", "dns--generators--dkim-keygen": "dkim-keygen",
    "dns--generators--dmarc-builder": "dmarc-builder", "dns--generators--caa-builder": "caa-builder", "dns--generators--tlsa-generator": "tlsa-gen", "dns--generators--sshfp-generator": "sshfp-gen", "dns--generators--svcb-https-builder": "svcb-https-builder",
    "dns--generators--naptr-builder": "naptr-builder", "dns--generators--loc-builder": "loc-builder", "dns--generators--rp-builder": "rp-builder", "dns--record-validator": "dns-record-validate", "dns--ttl-calculator": "ttl-calc",
    "dns--edns-size-estimator": "edns-size", "dns--zone--linter": "zone-lint", "dns--zone--diff": "zone-diff", "dns--zone--stats": "zone-stats", "dns--zone--name-length-checker": "dns-name-length",
    "dns--dnssec--dnskey-tag": "dnskey-tag", "dns--dnssec--ds-generator": "ds-gen", "dns--dnssec--nsec3-hash": "nsec3-hash", "dns--dnssec--cds-cdnskey-builder": "cds-builder", "dns--dnssec--rrsig-planner": "rrsig-planner",
    "dhcp--v4--options--option3-default-gateway": "dhcp-opt3", "dhcp--v4--options--options6-15-dns": "dhcp-opt6-15", "dhcp--v4--options--option51-lease-time": "dhcp-opt51", "dhcp--v4--options--option43-vendor-specific": "dhcp-opt43",
    "dhcp--v4--options--option60-vendor-class": "dhcp-opt60", "dhcp--v4--options--option61-clientid": "dhcp-opt61", "dhcp--v4--options--option82-relay-agent": "dhcp-opt82", "dhcp--v4--options--option119-domain-search": "dhcp-opt119",
    "dhcp--v4--options--option121-classless-routes": "dhcp-opt121", "dhcp--v4--options--option150-tftp-server": "dhcp-opt150", "dhcp--v4--options--pxe-boot-profile": "dhcp-pxe", "dhcp--v4--options--freeform-tlv": "dhcp-tlv",
    "dhcp--v6--options--option23-24-dns": "dhcpv6-dns", "dhcp--v6--options--option25-prefix-delegation": "dhcpv6-pd", "dhcp--v6--options--option39-fqdn": "dhcpv6-fqdn", "dhcp--v6--identity--duid-generator": "duid-gen",
    "dhcp--v6--identity--iaid-calculator": "iaid-calc", "dhcp--calculators--lease-time": "dhcp-lease-calc", "dhcp--tools--fingerprinting": "dhcp-fingerprint", "dhcp--kea-isc-snippets": "dhcp-config",
    "diagnostics--dns--query-performance": "server:dns-performance", "diagnostics--dns--spf-flatten": "server:spf-flatten", "diagnostics--http--cors-check": "server:cors-check", "diagnostics--http--compression": "server:compression-check",
    "diagnostics--tls--ocsp-stapling": "server:ocsp-stapling", "diagnostics--tls--cipher-presets": "tls-cipher-presets", "diagnostics--tls--banner": "server:tls-connection", "diagnostics--network--bgp-route-lookup": "server:bgp-lookup",
    "diagnostics--network--ipv6-connectivity-checker": "server:ipv6-check", "diagnostics--email--mail-tls-check": "server:mail-tls", "diagnostics--dns--glue-check": "server:dns-server",
    "reference--cidr": "ref-cidr", "reference--vlsm": "ref-vlsm", "reference--supernetting": "ref-supernetting", "reference--ipv6-address-types": "ref-ipv6-types", "reference--ipv6-prefix-lengths": "ref-ipv6-prefixes",
    "reference--ipv6-embedded-ipv4": "ref-ipv6-embedded-ipv4", "reference--ipv6-privacy-addresses": "ref-ipv6-privacy", "reference--common-subnets": "ref-common-subnets", "reference--network-classes": "ref-network-classes",
    "reference--reserved-ranges": "ref-reserved-ranges", "reference--special-use-ipv4": "ref-special-ipv4", "reference--private-vs-public-ip": "ref-private-public", "reference--cgnat": "ref-cgnat", "reference--link-local-apipa": "ref-link-local",
    "reference--multicast": "ref-multicast", "reference--reverse-dns": "ref-reverse-dns", "reference--reverse-zones": "ref-reverse-zones", "reference--icmp": "ref-icmp", "reference--arp-vs-ndp": "ref-arp-ndp", "reference--asn": "ref-asn",
    "reference--wildcard-masks": "ref-wildcard-masks", "reference--mtu-mss": "ref-mtu-mss",
    "subnetting--ipv4-subnet-calculator": "subnet-calc", "subnetting--ipv6-subnet-calculator": "ipv6-subnet", "subnetting--vlsm-calculator": "vlsm", "subnetting--supernet-calculator": "cidr-summarize", "subnetting--planner": "vlsm",
    "cidr--mask-converter--cidr-to-subnet-mask": "cidr-to-mask", "cidr--mask-converter--subnet-mask-to-cidr": "mask-to-cidr", "cidr--range-to-cidr": "range-to-cidr", "cidr--summarize": "cidr-summarize",
    "cidr--split": "cidr-split", "cidr--next-available": "cidr-next", "cidr--gaps": "cidr-gaps", "cidr--deaggregate": "cidr-deaggregate", "cidr--compare": "cidr-compare", "cidr--allocator": "vlsm",
    "cidr--alignment": "cidr-alignment", "cidr--wildcard-mask": "wildcard-mask", "cidr--set-operations--diff": "cidr-diff", "cidr--set-operations--overlap": "cidr-overlap", "cidr--set-operations--contains": "cidr-contains",
    "ip-address-convertor--representations": "ip-convert", "ip-address-convertor--random": "random-ip", "ip-address-convertor--validator": "ip-validate", "ip-address-convertor--enumerate": "cidr-to-range",
    "ip-address-convertor--notation--ipv6-expand": "ipv6-expand", "ip-address-convertor--notation--ipv6-compress": "ipv6-compress", "ip-address-convertor--notation--normalize": "ipv6-compress",
    "ip-address-convertor--families--ipv4-to-ipv6": "ip-convert", "ip-address-convertor--eui64": "eui64", "ip-address-convertor--ula-generator": "ipv6-ula", "ip-address-convertor--mac-address": "mac-format",
    "dns--generators--ptr-generator": "reverse-dns-name", "dns--reverse--ptr-generator": "reverse-dns-name", "dns--generators--idn-punycode": "punycode-encode", "dns--label-normalizer": "punycode-encode",
    "diagnostics--dns--lookup": "server:dns-lookup", "diagnostics--dns--reverse-lookup": "server:reverse-dns", "diagnostics--dns--propagation": "server:dns-propagation", "diagnostics--dns--spf-evaluator": "server:spf-check",
    "diagnostics--dns--dmarc-check": "server:dmarc-check", "diagnostics--dns--caa-effective": "server:caa-check", "diagnostics--dns--ns-soa-check": "server:dns-server", "diagnostics--dns--dnssec-adflag": "server:dnssec",
    "diagnostics--dns--dnssec-validation-chain": "server:dnssec", "diagnostics--dns--blacklist-checker": "server:blocklists", "diagnostics--dns--soa-serial": "server:dns-server",
    "diagnostics--http--headers": "server:headers", "diagnostics--http--redirect-trace": "server:redirects", "diagnostics--http--security": "server:http-security", "diagnostics--http--perf": "server:status",
    "diagnostics--http--cookie-security": "server:cookies", "diagnostics--tls--certificate": "server:ssl", "diagnostics--tls--versions": "server:tls-versions", "diagnostics--tls--alpn": "server:tls-connection",
    "diagnostics--tls--handshake-analyzer": "server:tls-connection", "diagnostics--tls--ct-log-search": "server:subdomains", "diagnostics--network--tcp-port-check": "server:port-check",
    "diagnostics--network--http-ping": "server:status", "diagnostics--network--asn-geo-lookup": "server:ip-whois", "diagnostics--email--mx-health": "server:mail-config", "diagnostics--email--spf-check": "server:spf-check",
    "diagnostics--email--dmarc-check": "server:dmarc-check", "diagnostics--rdap--domain": "server:whois", "diagnostics--rdap--ip": "server:ip-whois", "diagnostics--rdap--asn": "server:asn-lookup",
    "reference--ports": "port-reference",
  },
  webcheck: {
    quality: "server:quality",
    rank: "server:rank", carbon: "server:carbon",
    "get-ip": "server:get-ip", ssl: "server:ssl", dns: "server:dns-records", cookies: "server:cookies", "robots-txt": "server:robots-txt", headers: "server:headers", location: "server:server-info",
    hosts: "server:hosts", redirects: "server:redirects", "txt-records": "server:txt-records", status: "server:status", ports: "server:ports", "server-info": "server:server-info",
    domain: "server:whois", whois: "server:whois", dnssec: "server:dnssec", hsts: "server:hsts", "dns-server": "server:dns-server", "tech-stack": "server:tech-stack", sitemap: "server:sitemap",
    "security-txt": "server:security-txt", "linked-pages": "server:linked-pages", "social-tags": "server:social-tags", "mail-config": "server:mail-config", firewall: "server:firewall",
    "http-security": "server:http-security", archives: "server:archives", "block-lists": "server:blocklists", "tls-connection": "server:tls-connection", "tls-security-audit": "server:tls-versions",
    "tls-client-compat": "server:tls-versions", subdomains: "server:subdomains",
  },
  cyberchef: {
    // phase 3
    "To Float": "to-float", "From Float": "from-float", "To Bech32": "bech32-encode", "From Bech32": "bech32-decode", "Show Base64 offsets": "base64-offsets", "To Base92": "base92-encode", "From Base92": "base92-decode",
    "Encode text": "encode-text", "Decode text": "decode-text", "Text Encoding Brute Force": "text-encoding-brute", "Parse TLV": "parse-tlv", "MIME Decoding": "mime-decode",
    "Blowfish Encrypt": "blowfish-encrypt", "Blowfish Decrypt": "blowfish-decrypt", "DES Encrypt": "des-encrypt", "DES Decrypt": "des-decrypt", "Triple DES Encrypt": "3des-encrypt", "Triple DES Decrypt": "3des-decrypt",
    "Rabbit": "rabbit", "RC6 Encrypt": "rc6-encrypt", "RC6 Decrypt": "rc6-decrypt", "PRESENT Encrypt": "present-encrypt", "PRESENT Decrypt": "present-decrypt", "Derive EVP key": "evp-key", "Bcrypt": "bcrypt-hash", "Enigma": "enigma",
    "HTTP request": "server:http-request", "Strip HTTP headers": "strip-http-headers", "Dechunk HTTP response": "dechunk-http", "Parse Ethernet frame": "parse-ethernet", "Parse IPv4 header": "parse-ipv4", "Strip IPv4 header": "strip-ipv4",
    "Parse TCP": "parse-tcp", "Strip TCP header": "strip-tcp", "Parse TLS record": "parse-tls-record", "Parse UDP": "parse-udp", "Strip UDP header": "strip-udp", "Protobuf Decode": "protobuf-decode", "Protobuf Encode": "protobuf-encode",
    "JA3 Fingerprint": "ja3", "JA3S Fingerprint": "ja3s", "JA4 Fingerprint": "ja4", "JA4Server Fingerprint": "ja4s", "HASSH Client Fingerprint": "hassh", "HASSH Server Fingerprint": "hassh-server",
    "Fuzzy Match": "fuzzy-match", "Offset checker": "offset-checker", "Show on map": "show-on-map", "Sleep": "sleep", "XPath expression": "xpath", "CSS selector": "css-selector", "RAKE": "rake",
    "Extract EXIF": "extract-exif", "Extract ID3": "extract-id3", "Zip": "zip", "Unzip": "unzip", "Tar": "tar", "Untar": "untar", "LZ4 Decompress": "lz4-decompress", "LZ4 Compress": "lz4-compress",
    "LZNT1 Decompress": "lznt1-decompress", "XPRESS Decompress": "xpress-decompress", "SHA0": "sha0", "SM3": "sm3", "Whirlpool": "whirlpool", "BLAKE3": "blake3", "SSDEEP": "ssdeep", "CTPH": "ssdeep",
    "Compare SSDEEP hashes": "ssdeep-compare", "Compare CTPH hashes": "ssdeep-compare", "Bcrypt compare": "bcrypt-compare", "Bcrypt parse": "bcrypt-parse", "Argon2": "argon2", "Argon2 compare": "argon2-compare", "LM Hash": "lm-hash",
    "Generic Code Beautify": "code-beautify", "JavaScript Minify": "js-minify", "BSON serialise": "bson-serialise", "BSON deserialise": "bson-deserialise",
    "Detect File Type": "detect-file-type", "Scan for Embedded Files": "scan-embedded", "Remove EXIF": "remove-exif", "Extract RGBA": "extract-rgba", "View Bit Plane": "bit-plane", "Randomize Colour Palette": "randomize-palette", "Extract LSB": "extract-lsb", "ELF Info": "elf-info",
    "Render Image": "render-image", "Generate Image": "generate-image", "Split Colour Channels": "split-channels", "Rotate Image": "rotate-image", "Resize Image": "resize-image", "Blur Image": "blur-image", "Dither Image": "dither-image",
    "Invert Image": "invert-image", "Flip Image": "flip-image", "Crop Image": "crop-image", "Image Brightness / Contrast": "brightness-contrast", "Image Opacity": "image-opacity", "Image Filter": "image-filter", "Contain Image": "contain-image",
    "Cover Image": "cover-image", "Image Hue/Saturation/Lightness": "hue-saturation", "Sharpen Image": "sharpen-image", "Normalise Image": "normalise-image", "Convert Image Format": "convert-image", "Add Text To Image": "add-text-image",
    "Hex Density chart": "hex-density", "Scatter chart": "scatter-chart", "Series chart": "series-chart", "Heatmap chart": "heatmap-chart", "P-list Viewer": "plist-viewer", "Generate QR Code": "qr-generate", "Numberwang": "numberwang",
    "Magic": "magic", "Comment": "comment",
    // phase 2
    "To Hexdump": "to-hexdump", "From Hexdump": "from-hexdump", "To Base45": "base45-encode", "From Base45": "base45-decode", "To Base62": "base62-encode", "From Base62": "base62-decode",
    "To Base85": "base85-encode", "From Base85": "base85-decode", "To Base": "to-radix", "From Base": "from-radix", "To BCD": "to-bcd", "From BCD": "from-bcd", "Text-Integer Conversion": "text-to-integer",
    "Normalise Unicode": "normalise-unicode", "Escape Smart Characters": "escape-smart", "From Punycode": "punycode-decode", "To Hex Content": "to-hex-content", "From Hex Content": "from-hex-content",
    "PEM to Hex": "pem-to-hex", "Hex to PEM": "hex-to-pem", "Parse ASN.1 hex string": "parse-asn1", "Swap endianness": "swap-endianness", "To MessagePack": "msgpack-encode", "From MessagePack": "msgpack-decode",
    "To Braille": "braille-encode", "From Braille": "braille-decode", "CBOR Encode": "cbor-encode", "CBOR Decode": "cbor-decode", "YAML to JSON": "yaml-to-json", "JSON to YAML": "json-to-yaml2",
    "Caret/M-decode": "caret-decode", "Rison Encode": "rison-encode", "Rison Decode": "rison-decode", "To Modhex": "modhex-encode", "From Modhex": "modhex-decode", "To COBS": "cobs-encode", "From COBS": "cobs-decode",
    "RC4": "rc4", "RC4 Drop": "rc4-drop", "ChaCha": "chacha20", "Salsa20": "salsa20", "XSalsa20": "xsalsa20", "ROT13 Brute Force": "rot13-brute", "ROT47 Brute Force": "rot47-brute", "ROT8000": "rot8000",
    "XOR Brute Force": "xor-brute", "TEA Encrypt": "tea-encrypt", "TEA Decrypt": "tea-decrypt", "XTEA Encrypt": "xtea-encrypt", "XTEA Decrypt": "xtea-decrypt", "XXTEA Encrypt": "xxtea-encrypt", "XXTEA Decrypt": "xxtea-decrypt",
    "Bifid Cipher Encode": "bifid-encode", "Bifid Cipher Decode": "bifid-decode", "Caesar Box Cipher": "caesar-box", "Rail Fence Cipher Encode": "rail-fence-encode", "Rail Fence Cipher Decode": "rail-fence-decode",
    "CipherSaber2 Encrypt": "ciphersaber2-encrypt", "CipherSaber2 Decrypt": "ciphersaber2-decrypt", "Cetacean Cipher Encode": "cetacean-encode", "Cetacean Cipher Decode": "cetacean-decode", "Substitute": "substitute",
    "Derive HKDF key": "hkdf", "Scrypt": "scrypt", "Citrix CTX1 Encode": "ctx1-encode", "Citrix CTX1 Decode": "ctx1-decode", "AES Key Wrap": "aes-key-wrap", "AES Key Unwrap": "aes-key-unwrap",
    "Pseudo-Random Prime Generator": "prime-gen", "Fernet Encrypt": "fernet-encrypt", "Fernet Decrypt": "fernet-decrypt", "Flask Session Decode": "flask-session-decode",
    "Parse X.509 certificate": "parse-x509", "Parse X.509 CRL": "parse-crl", "Hex to Object Identifier": "hex-to-oid", "Object Identifier to Hex": "oid-to-hex", "PEM to JWK": "pem-to-jwk", "JWK to PEM": "jwk-to-pem",
    "RSA Sign": "rsa-sign", "RSA Verify": "rsa-verify", "RSA Encrypt": "rsa-encrypt", "RSA Decrypt": "rsa-decrypt", "Generate ECDSA Key Pair": "ecdsa-keygen", "ECDSA Signature Conversion": "ecdsa-sig-convert",
    "ECDSA Sign": "ecdsa-sign", "ECDSA Verify": "ecdsa-verify", "Parse SSH Host Key": "parse-ssh-key", "Parse CSR": "parse-csr", "Public Key from Certificate": "pubkey-from-cert", "Public Key from Private Key": "pubkey-from-private",
    "Set Union": "set-union", "Set Intersection": "set-intersection", "Set Difference": "set-difference", "Symmetric Difference": "set-symmetric", "Cartesian Product": "cartesian-product", "Power Set": "power-set",
    "OR": "bitwise-or", "NOT": "bitwise-not", "AND": "bitwise-and", "ADD": "bitwise-add", "SUB": "bitwise-sub", "Sum": "arith-sum?operation=Sum", "Subtract": "arith-sum?operation=Subtract", "Multiply": "arith-sum?operation=Multiply",
    "Divide": "arith-sum?operation=Divide", "MOD": "arith-sum?operation=MOD", "Extended GCD": "extended-gcd", "Modular Exponentiation": "mod-exp", "Modular Inverse": "mod-inverse", "Mean": "arith-stats", "Median": "arith-stats",
    "Standard Deviation": "arith-stats", "Bit shift left": "bit-shift?direction=Left", "Bit shift right": "bit-shift?direction=Right", "Rotate left": "bit-rotate?direction=Left", "Rotate right": "bit-rotate?direction=Right",
    "VarInt Encode": "varint-encode", "VarInt Decode": "varint-decode", "Format MAC addresses": "mac-format", "Encode NetBIOS Name": "netbios-encode", "Decode NetBIOS Name": "netbios-decode", "IPv6 Transition Addresses": "ipv4-to-ipv6",
    "Remove Diacritics": "remove-diacritics", "Unicode Text Format": "unicode-text-format", "Convert to NATO alphabet": "nato-alphabet", "Convert Leet Speak": "leet-speak",
    "Remove null bytes": "remove-null", "Remove ANSI Escape Codes": "remove-ansi", "To Case Insensitive Regex": "to-case-insensitive-regex", "From Case Insensitive Regex": "from-case-insensitive-regex", "Get All Casings": "all-casings",
    "To Table": "to-table", "Shuffle": "shuffle", "Filter": "filter", "Expand alphabet range": "expand-range", "Drop bytes": "take-drop-bytes?mode=Drop", "Take bytes": "take-drop-bytes?mode=Take", "Pad lines": "pad-lines",
    "Hamming Distance": "hamming", "Levenshtein Distance": "levenshtein", "Convert distance": "convert-distance", "Convert area": "convert-area", "Convert mass": "convert-mass", "Convert speed": "convert-speed",
    "Convert co-ordinate format": "convert-coordinates", "Parse ObjectID timestamp": "objectid-timestamp", "File Tree": "file-tree", "Wrap": "wrap", "Take nth bytes": "nth-bytes?mode=Take", "Drop nth bytes": "nth-bytes?mode=Drop",
    "Parse DateTime": "parse-datetime", "Translate DateTime Format": "translate-datetime", "Windows Filetime to UNIX Timestamp": "filetime-to-unix", "UNIX Timestamp to Windows Filetime": "unix-to-filetime", "DateTime Delta": "datetime-delta", "Get Time": "get-time",
    "Strings": "strings", "JPath expression": "json-path", "Template": "template",
    "Raw Deflate": "raw-deflate", "Raw Inflate": "raw-inflate", "Zlib Deflate": "zlib-deflate", "Zlib Inflate": "zlib-inflate", "Gzip": "gzip", "Gunzip": "gunzip", "LZString Decompress": "lzstring-decompress", "LZString Compress": "lzstring-compress",
    "Generate all checksums": "all-checksums", "MD4": "md4", "SHA3": "sha3", "Keccak": "keccak", "Shake": "shake", "RIPEMD": "ripemd160", "BLAKE2b": "blake2b", "BLAKE2s": "blake2s", "CMAC": "cmac", "NT Hash": "nt-hash",
    "MurmurHash3": "murmur3", "Fletcher-8 Checksum": "fletcher?bits=8", "Fletcher-16 Checksum": "fletcher?bits=16", "Fletcher-32 Checksum": "fletcher?bits=32", "Fletcher-64 Checksum": "fletcher?bits=64", "CRC Checksum": "crc-any",
    "TCP/IP Checksum": "inet-checksum", "XOR Checksum": "xor-checksum", "Parity Bit": "parity-bit",
    "XML Minify": "xml-minify", "SQL Beautify": "sql-format", "SQL Minify": "sql-minify", "CSS Beautify": "css-format", "CSS Minify": "css-minify", "PHP Deserialize": "php-unserialize", "PHP Serialize": "php-serialize", "Render Markdown": "markdown-to-html",
    "Index of Coincidence": "index-of-coincidence", "Chi Square": "chi-square", "Generate De Bruijn Sequence": "de-bruijn", "Analyse UUID": "analyse-uuid", "Generate HOTP": "hotp", "Haversine distance": "haversine",
    "HTML To Text": "html-strip", "Generate Lorem Ipsum": "lorem-ipsum", "XKCD Random Number": "xkcd-random", "From UNIX Timestamp": "unix-timestamp", "To UNIX Timestamp": "unix-timestamp",
    "To Base64": "base64-encode", "From Base64": "base64-decode", "To Base32": "base32-encode", "From Base32": "base32-decode", "To Base58": "base58-encode", "From Base58": "base58-decode",
    "To Hex": "hex-encode", "From Hex": "hex-decode", "To Binary": "binary-encode", "From Binary": "binary-decode", "To Octal": "octal-encode", "From Octal": "octal-decode",
    "To Decimal": "decimal-encode", "From Decimal": "decimal-decode", "To Charcode": "charcode-encode", "From Charcode": "charcode-decode", "URL Encode": "url-encode", "URL Decode": "url-decode",
    "To HTML Entity": "html-encode", "From HTML Entity": "html-decode", "Escape Unicode Characters": "unicode-escape", "Unescape Unicode Characters": "unicode-unescape", "Escape string": "unicode-escape",
    "Unescape string": "unicode-unescape", "To Quoted Printable": "quoted-printable-encode", "From Quoted Printable": "quoted-printable-decode", "To Punycode": "punycode-encode",
    "ROT13": "rot13", "ROT47": "rot47", "Atbash Cipher": "atbash", "Vigenère Encode": "vigenere-encode", "Vigenère Decode": "vigenere-decode", "Affine Cipher Encode": "affine-encode",
    "Affine Cipher Decode": "affine-decode", "To Morse Code": "morse-encode", "From Morse Code": "morse-decode", "A1Z26 Cipher Encode": "a1z26-encode", "A1Z26 Cipher Decode": "a1z26-decode",
    "Bacon Cipher Encode": "bacon-encode", "Bacon Cipher Decode": "bacon-decode", "XOR": "xor", "Reverse": "reverse", "AES Encrypt": "aes-encrypt", "AES Decrypt": "aes-decrypt",
    "Derive PBKDF2 key": "pbkdf2", "Generate RSA Key Pair": "rsa-keygen", "JWT Decode": "jwt-decode", "JWT Sign": "jwt-sign", "JWT Verify": "jwt-verify", "Generate TOTP": "otp",
    "MD5": "md5", "SHA1": "sha1", "SHA2": "sha256", "HMAC": "hmac", "Adler-32 Checksum": "adler32", "Generate all hashes": "hash-all", "Analyse hash": "hash-identify",
    "Luhn Checksum": "luhn-check", "Generate UUID": "uuid", "Pseudo-Random Number Generator": "random-bytes", "Pseudo-Random Integer Generator": "random-number",
    "To Upper case": "case-convert?case=UPPERCASE", "To Lower case": "case-convert?case=lowercase", "To Snake case": "case-convert?case=snake_case", "To Camel case": "case-convert?case=camelCase",
    "To Kebab case": "case-convert?case=kebab-case", "Swap case": "case-convert?case=aLtErNaTiNg", "Alternating Caps": "case-convert?case=aLtErNaTiNg", "Sort": "sort-lines", "Unique": "unique-lines",
    "Remove whitespace": "remove-whitespace", "Find / Replace": "find-replace", "Regular expression": "regex-tester", "Count occurrences": "count-occurrences", "Head": "head-tail?which=Head",
    "Tail": "head-tail?which=Tail", "Add line numbers": "add-line-numbers", "Remove line numbers": "remove-line-numbers", "Diff": "text-diff", "Split": "split-join", "Strip HTML tags": "html-strip",
    "Frequency distribution": "frequency-analysis", "Entropy": "entropy", "JSON Beautify": "json-format", "JSON Minify": "json-minify", "JSON to CSV": "json-to-csv", "CSV to JSON": "csv-to-json", "XML Beautify": "xml-format", "Parse URI": "url-parse", "Parse User Agent": "user-agent", "Parse colour code": "color-convert", "Parse UNIX file permissions": "chmod",
    "Change IP format": "ip-convert", "Parse IP range": "cidr-to-range", "Group IP addresses": "ip-sort", "Parse IPv6 address": "ip-convert", 
    "Defang URL": "defang-url", "Fang URL": "fang-url", "Defang IP Addresses": "defang-url", "Extract URLs": "extract-urls", "Extract email addresses": "extract-emails",
    "Extract IP addresses": "extract-ipv4", "Extract domains": "extract-domains", "Extract MAC addresses": "extract-mac", "Extract hashes": "extract-hashes", "Extract file paths": "extract-file-paths",
    "Extract dates": "extract-dates", "Convert data units": "byte-convert", "DNS over HTTPS": "server:dns-lookup",
  },
};

// Web-Check ships one flat list; group its checks so the tab is navigable.
const WEBCHECK_GROUPS = {
  "DNS & Domain": ["dns", "txt-records", "dnssec", "dns-server", "domain", "whois", "subdomains"],
  "TLS & Certificates": ["ssl", "tls-connection", "tls-security-audit", "tls-client-compat", "hsts"],
  "HTTP & Security": ["headers", "http-security", "cookies", "redirects", "firewall", "security-txt", "status"],
  "Infrastructure": ["get-ip", "location", "server-info", "hosts", "ports", "trace-route", "carbon"],
  "Content & SEO": ["robots-txt", "sitemap", "linked-pages", "social-tags", "tech-stack", "quality", "screenshot", "archives", "rank"],
  "Email": ["mail-config"],
  "Threat Intelligence": ["vulnerabilities", "block-lists", "threats"],
};
const webcheckGroup = (id) => Object.entries(WEBCHECK_GROUPS).find(([, ids]) => ids.includes(id))?.[0] || "Other checks";
// The four toolkits. Only tools with a native implementation are published (link-only tools are excluded).
const TABS = [
  { id: "it-toolkit", source: "ittools", name: "IT Toolkit", icon: "toolbox", accent: "#22d3ee",
    tagline: "Generators, converters and formatters for everyday dev and sysadmin work.",
    description: "Everyday developer and sysadmin utilities: token and UUID generators, encoders, converters, formatters, JWT and JSON tools, and quick calculators.",
    sourceUrl: "https://ittools.sajinshivdas.online", link: (t) => `https://ittools.sajinshivdas.online${t.path}` },
  { id: "cyberchef-toolkit", source: "cyberchef", name: "CyberChef Toolkit", icon: "flask", accent: "#a78bfa",
    tagline: "Encode, decode, encrypt, hash and analyse data, and chain it all into recipes.",
    description: "The cyber Swiss-army knife: encodings, ciphers, hashes, public-key crypto, data formats, compression, forensics and packet parsing, with a recipe builder that chains operations.",
    sourceUrl: "https://cyberchef.sajinshivdas.online", link: (t) => `https://cyberchef.sajinshivdas.online/#recipe=${encodeURIComponent(t.name.replace(/ /g, "_"))}()` },
  { id: "web-toolkit", source: "webcheck", name: "Web Toolkit", icon: "radar", accent: "#34d399",
    tagline: "Live intelligence on any website: DNS, TLS, headers, mail and exposure.",
    description: "Website intelligence and OSINT that runs live from the server: infrastructure, TLS and certificates, DNS, HTTP security headers, content, mail security and threat checks.",
    sourceUrl: "https://webcheck.sajinshivdas.online", link: () => "https://webcheck.sajinshivdas.online/check" },
  { id: "network-toolkit", source: "networking-toolbox", name: "Network Toolkit", icon: "network", accent: "#f472b6",
    tagline: "Subnetting, CIDR, IPv6, DNS, DHCP and live network diagnostics.",
    description: "Network engineering in one place: subnet and CIDR maths, IP conversions, DNS record and DNSSEC builders, DHCP option encoders, live lookups and quick-reference sheets.",
    sourceUrl: "https://networking-toolbox.sajinshivdas.online", link: (t) => `https://networking-toolbox.sajinshivdas.online${t.path}` },
];

// Category cards: a one-line description and an icon for each category (Network Toolkit uses "Group · Sub" names;
// the card is per group). Admins can edit all of this later.
const CAT_META = {
  ittools: {
    "Crypto": ["key", "Tokens, hashes, UUIDs, HMACs, bcrypt, BIP39 phrases and password checks."],
    "Converter": ["shuffle", "Convert between bases, encodings, colours, dates, cases and data formats."],
    "Web": ["globe", "URL, HTML and JWT helpers, user-agent parsing, HTTP status codes and more."],
    "Images and videos": ["image", "Generate QR codes and SVG placeholders, and convert images."],
    "Development": ["code", "Formatters, crontab and regex helpers, chmod, Docker and Git cheats."],
    "Network": ["network", "IPv4 subnets, ranges and MAC addresses, IPv6 ULAs and conversions."],
    "Math": ["calculator", "Evaluate expressions, ETA and percentage calculators."],
    "Measurement": ["gauge", "Benchmarks, chronometers and temperature conversions."],
    "Text": ["type", "Lorem ipsum, diffs, statistics, obfuscation and Unicode conversions."],
    "Data": ["database", "Phone numbers, IBANs and other structured data validators."],
  },
  cyberchef: {
    "Data format": ["binary", "Base64, hex, binary, URL, HTML entities, JSON, CSV, YAML, CBOR and more."],
    "Encryption / Encoding": ["lock", "Symmetric ciphers, classical ciphers and text encodings."],
    "Public Key": ["key", "Parse certificates, CSRs and keys; RSA and ECDSA sign, verify and encrypt."],
    "Arithmetic / Logic": ["calculator", "XOR, bit shifts, sums, means, medians and boolean operations."],
    "Networking": ["network", "Parse IPs, URLs, user agents, packets and TLS handshakes; JA3/JA4 fingerprints."],
    "Language": ["type", "Character encodings, Unicode normalisation and text analysis."],
    "Utils": ["wrench", "Split, join, sort, filter, pad, diff and transform text."],
    "Date / Time": ["clock", "Parse, convert and format timestamps across epochs and time zones."],
    "Extractors": ["filter", "Pull IPs, emails, URLs, domains, hashes and file paths out of text."],
    "Compression": ["archive", "Gzip, Zlib, Deflate, Zip, Tar, LZ4, LZString and more."],
    "Hashing": ["hash", "MD, SHA-1/2/3, BLAKE, CRCs, HMAC, bcrypt, Argon2 and fuzzy hashes."],
    "Code tidy": ["code", "Beautify and minify JSON, XML, SQL, CSS and JavaScript."],
    "Forensics": ["search", "Detect file types, extract embedded files, parse EXIF, ELF and plists."],
    "Multimedia": ["image", "Image edits, QR codes, charts and colour tools that run in the browser."],
    "Other": ["sparkle", "Entropy, Magic auto-detection, BIP39, Enigma and more."],
    "Flow control": ["layers", "Comments and jumps for building recipes."],
  },
  webcheck: {
    "Infrastructure": ["server", "IP, location, server info, open ports and carbon footprint."],
    "TLS & Certificates": ["shield", "Certificate chain, TLS versions, cipher suites and OCSP stapling."],
    "DNS & Domain": ["globe", "DNS records, DNSSEC, WHOIS, subdomains, zone transfers and DNS trace."],
    "HTTP & Security": ["lock", "Security headers, HSTS, cookies, redirects, CORS and HTTP requests."],
    "Content & SEO": ["search", "robots.txt, sitemaps, social tags, linked pages, rank and page quality."],
    "Email": ["mail", "MX, SPF, DKIM, DMARC and mail server TLS."],
    "Threat Intelligence": ["target", "DNS blocklist checks across major reputation lists."],
  },
  "networking-toolbox": {
    "Subnetting": ["grid", "IPv4 and IPv6 subnet calculators, VLSM, supernets and subnet planning."],
    "CIDR": ["layers", "CIDR masks, ranges, summarisation, splitting, gaps and set operations."],
    "IP Tools": ["binary", "Convert, validate, enumerate and generate IPv4 and IPv6 addresses."],
    "DNS Tools": ["globe", "Build DNS records, reverse zones, zone files and DNSSEC material."],
    "DHCP": ["plug", "Encode DHCPv4 and DHCPv6 options, plan scopes and generate configs."],
    "Lookups": ["radar", "Live DNS, HTTP, TLS, network, email and RDAP diagnostics."],
    "Reference": ["book", "Quick-reference sheets for CIDR, IPv6, special addresses and protocols."],
  },
};

// Recommended starting points shown on the landing page (admins can change these).
const FEATURED = {
  "it-toolkit": ["token-generator", "hash-text", "jwt-parser", "ipv4-subnet-calculator"],
  "cyberchef-toolkit": ["magic", "aes-encrypt", "parse-x-509-certificate", "ja3-fingerprint"],
  "web-toolkit": ["ssl", "headers", "mail-config", "dns"],
  "network-toolkit": ["subnetting--ipv4-subnet-calculator", "cidr--summarize", "diagnostics--dns--lookup"],
};

const missing = [];
function nativeOf(spec) {
  if (!spec) return null;
  const [key, q] = spec.split("?"); const server = key.startsWith("server:"); const op = server ? key.slice(7) : key;
  if (!(server ? serverOps[op] : registry[op])) { missing.push(spec); return null; }
  return { op, mode: server ? "server" : "client", preset: q ? Object.fromEntries(new URLSearchParams(q)) : undefined };
}

const SITE_DEFAULTS = {
  title: "Infosec Tools", brandPrefix: "Infosec", brandSuffix: "Tools",
  eyebrow: "Rebuilt natively with REA",
  heading: "The workbench for", highlight: "everyday security", headingEnd: "tooling.",
  lead: "{tools} tools across {toolkits} toolkits that run in your browser or live from the server: IT utilities, CyberChef operations, website recon and network engineering, all in one place.",
  footer: "Infosec Tools combines four self-hosted toolkits, rebuilt natively after static analysis with REA. Browser tools never send your input anywhere; live checks run on this server.",
  theme: "dark",
};

const topCat = (c) => c.split(" · ")[0];
const catalog = { version: 2, generatedAt: new Date().toISOString(), title: SITE_DEFAULTS.title, site: SITE_DEFAULTS, tabs: [] };
let excluded = 0;
for (const tab of TABS) {
  const src = seed(`${tab.source}.json`); const seen = new Set(); const tools = [];
  const cats = [...src.categories, ...(src.uncategorized?.length ? [{ name: "Other", tools: src.uncategorized }] : [])];
  for (const cat of cats) for (const t of cat.tools) {
    if (seen.has(t.id)) continue; seen.add(t.id);
    const native = nativeOf(MAP[tab.source][tab.source === "cyberchef" ? t.name : t.id]);
    if (!native) { excluded++; continue; } // link-only tools are not published
    let category = tab.source === "webcheck" ? webcheckGroup(t.id) : tab.source === "networking-toolbox" && t.group ? `${cat.name} · ${t.group}` : cat.name;
    category = category.replace(/^Ref( · |$)/, "Reference$1");
    tools.push({ id: t.id, name: t.name, description: t.description || t.use || "", category, keywords: t.keywords || [], native, external: tab.link(t), visible: true,
      featured: FEATURED[tab.id].includes(t.id) || undefined });
  }
  const present = [...new Set(tools.map((x) => topCat(x.category)))];
  const meta = CAT_META[tab.source];
  for (const c of present) if (!meta[c]) { console.error(`No CAT_META for ${tab.source} / ${c}`); process.exit(1); }
  for (const id of FEATURED[tab.id]) if (!tools.some((x) => x.id === id)) { console.error(`Featured tool ${tab.id}/${id} not found`); process.exit(1); }
  catalog.tabs.push({ id: tab.id, name: tab.name, tagline: tab.tagline, description: tab.description, icon: tab.icon, accent: tab.accent, source: tab.source, sourceUrl: tab.sourceUrl, visible: true,
    categories: present.map((c) => ({ name: c, icon: meta[c][0], description: meta[c][1] })), tools });
}
if (missing.length) { console.error("Unknown ops in MAP:", missing.join(", ")); process.exit(1); }
fs.writeFileSync(path.join(root, "seed", "catalog.json"), JSON.stringify(catalog, null, 1));
for (const t of catalog.tabs) console.log(`${t.name.padEnd(18)} ${String(t.tools.length).padStart(3)} tools in ${t.categories.length} categories`);
console.log(`Total ${catalog.tabs.reduce((n, t) => n + t.tools.length, 0)} tools published; ${excluded} link-only tools excluded`);

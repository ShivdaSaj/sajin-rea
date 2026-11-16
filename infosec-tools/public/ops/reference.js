// Network reference sheets (Networking Toolbox "Ref" section) and TLS cipher presets.
// Each is a searchable text page: the input box filters lines by keyword.
const filterRef = (text) => (i) => { const q = String(i || "").trim().toLowerCase(); if (!q) return text; const out = text.split("\n").filter((l) => l.toLowerCase().includes(q)); return out.length ? out.join("\n") : `No lines match "${i}"`; };
const ref = (name, text) => ({ name, run: filterRef(text.trim()), placeholder: "Filter (optional)" });

export const ops = {
  "ref-cidr": ref("CIDR Notation", `
CIDR  Netmask          Wildcard         Addresses      Usable hosts   /24s
/8    255.0.0.0        0.255.255.255    16,777,216     16,777,214     65,536
/12   255.240.0.0      0.15.255.255     1,048,576      1,048,574      4,096
/16   255.255.0.0      0.0.255.255      65,536         65,534         256
/20   255.255.240.0    0.0.15.255       4,096          4,094          16
/21   255.255.248.0    0.0.7.255        2,048          2,046          8
/22   255.255.252.0    0.0.3.255        1,024          1,022          4
/23   255.255.254.0    0.0.1.255        512            510            2
/24   255.255.255.0    0.0.0.255        256            254            1
/25   255.255.255.128  0.0.0.127        128            126            1/2
/26   255.255.255.192  0.0.0.63         64             62             1/4
/27   255.255.255.224  0.0.0.31         32             30             1/8
/28   255.255.255.240  0.0.0.15         16             14             1/16
/29   255.255.255.248  0.0.0.7          8              6              1/32
/30   255.255.255.252  0.0.0.3          4              2              1/64
/31   255.255.255.254  0.0.0.1          2              2 (RFC 3021)   point-to-point
/32   255.255.255.255  0.0.0.0          1              1              host route
Rule: addresses = 2^(32 − prefix); usable = addresses − 2 (network + broadcast), except /31 and /32.`),
  "ref-vlsm": ref("VLSM", `
Variable Length Subnet Masking: carve one block into subnets of different sizes.
1. Sort requirements largest first.
2. For each, pick the smallest prefix with 2^(32−p) − 2 ≥ hosts.
3. Allocate from the start of the block, aligned to the subnet size.
4. Continue from the next free aligned address.
Hosts needed → prefix: 2→/30  6→/29  14→/28  30→/27  62→/26  126→/25  254→/24  510→/23  1022→/22
Example 192.168.0.0/24 for 100, 50, 20, 2 hosts:
  100 → 192.168.0.0/25   (126 usable)
  50  → 192.168.0.128/26 (62)
  20  → 192.168.0.192/27 (30)
  2   → 192.168.0.224/30 (2)
Use the VLSM Subnet Planner tool to compute this automatically.`),
  "ref-supernetting": ref("Supernetting / Route Summarisation", `
Supernetting combines contiguous networks into one shorter prefix.
Requirements: the networks must be contiguous, the count must be a power of two, and the first must be aligned to the combined size.
Example: 10.0.0.0/24 + 10.0.1.0/24 + 10.0.2.0/24 + 10.0.3.0/24 → 10.0.0.0/22
Not summarisable to one prefix: 10.0.1.0/24 + 10.0.2.0/24 (10.0.1.0 is not /23-aligned) → stays two routes.
Benefits: smaller routing tables, fewer updates, route stability. Risk: summarising space you don't own can black-hole traffic.
Use the CIDR Summarizer tool for exact results.`),
  "ref-ipv6-types": ref("IPv6 Address Types", `
::/128            Unspecified
::1/128           Loopback
::ffff:0:0/96     IPv4-mapped
64:ff9b::/96      NAT64 well-known prefix
64:ff9b:1::/48    Local-use NAT64
100::/64          Discard-only
2000::/3          Global unicast
2001::/32         Teredo
2001:db8::/32     Documentation
2002::/16         6to4
3fff::/20         Documentation (RFC 9637)
fc00::/7          Unique local (ULA; fd00::/8 in practice)
fe80::/10         Link-local unicast
ff00::/8          Multicast (ff02::1 all nodes, ff02::2 all routers, ff02::1:ff00:0/104 solicited-node)`),
  "ref-ipv6-prefixes": ref("IPv6 Prefix Lengths", `
/128  single address (loopback, anycast, host route)
/127  point-to-point links (RFC 6164)
/64   standard LAN/VLAN subnet — required for SLAAC
/60   small site or home (16 /64s)
/56   typical home/small business allocation (256 /64s)
/48   typical site/enterprise allocation (65,536 /64s)
/40–/32  ISP/LIR allocations (/32 = 65,536 /48s)
/29   common RIR allocation to large ISPs
Never subnet a LAN smaller than /64 if you use SLAAC.`),
  "ref-ipv6-embedded-ipv4": ref("IPv6 Embedded IPv4", `
IPv4-mapped        ::ffff:a.b.c.d             dual-stack sockets
IPv4-compatible    ::a.b.c.d                  deprecated
6to4               2002:AABB:CCDD::/48        IPv4 in bits 16–47
NAT64 / DNS64      64:ff9b::a.b.c.d           RFC 6052 /96
Teredo             2001:0:SSSS:SSSS:flags:port^:client^   server + obfuscated client
ISATAP             prefix::0:5efe:a.b.c.d     interface ID carries IPv4
Use the Embedded IPv4 Extractor tool to decode any of these.`),
  "ref-ipv6-privacy": ref("IPv6 Privacy Addresses", `
SLAAC with EUI-64 builds the interface ID from the MAC (fffe inserted, U/L bit flipped) — trackable across networks.
RFC 8981 temporary addresses: random interface IDs, rotated (typically daily), used for outbound connections.
RFC 7217 stable-privacy: stable per network, but not derived from the MAC — the modern default for the stable address.
Linux: net.ipv6.conf.*.use_tempaddr=2 · Windows: on by default · macOS/iOS: on by default.
Servers usually want static or stable addresses; clients benefit from temporary ones.`),
  "ref-common-subnets": ref("Common Subnets", `
Use case                     Prefix   Usable hosts
Point-to-point link          /30 /31  2
Small office VLAN            /26      62
Typical LAN / VLAN           /24      254
Large Wi-Fi / campus VLAN    /22      1,022
Docker default bridge        /16      65,534  (172.17.0.0/16)
Kubernetes pod CIDR          /16 /14  per cluster (e.g. 10.244.0.0/16)
AWS VPC (max)                /16      VPC sizes /16 – /28; AWS reserves 5 IPs per subnet
Azure VNet subnet            /24      Azure reserves 5 IPs per subnet
Home router default          /24      192.168.0.0/24 or 192.168.1.0/24`),
  "ref-network-classes": ref("Classful Network Classes", `
Class  First octet  Leading bits  Default mask     Networks     Hosts/network
A      1–126        0             255.0.0.0 /8     126          16,777,214
B      128–191      10            255.255.0.0 /16  16,384       65,534
C      192–223      110           255.255.255.0/24 2,097,152    254
D      224–239      1110          multicast        —            —
E      240–255      1111          reserved         —            —
127.0.0.0/8 is loopback. Classful addressing was replaced by CIDR in 1993 (RFC 1519) but the terms persist.`),
  "ref-reserved-ranges": ref("Reserved IPv4 Ranges", `
0.0.0.0/8          "This network"
10.0.0.0/8         Private (RFC 1918)
100.64.0.0/10      Carrier-grade NAT (RFC 6598)
127.0.0.0/8        Loopback
169.254.0.0/16     Link-local (APIPA)
172.16.0.0/12      Private (RFC 1918)
192.0.0.0/24       IETF protocol assignments
192.0.2.0/24       Documentation (TEST-NET-1)
192.88.99.0/24     Deprecated 6to4 relay anycast
192.168.0.0/16     Private (RFC 1918)
198.18.0.0/15      Benchmarking (RFC 2544)
198.51.100.0/24    Documentation (TEST-NET-2)
203.0.113.0/24     Documentation (TEST-NET-3)
224.0.0.0/4        Multicast
240.0.0.0/4        Reserved (Class E)
255.255.255.255/32 Limited broadcast`),
  "ref-special-ipv4": ref("Special-Use IPv4 (RFC 6890)", `
Address/block        Source  Dest  Forwardable  Global  Purpose
0.0.0.0/8            yes     no    no           no      This host on this network
10.0.0.0/8           yes     yes   yes          no      Private-use
100.64.0.0/10        yes     yes   yes          no      Shared address space (CGN)
127.0.0.0/8          no      no    no           no      Loopback
169.254.0.0/16       yes     yes   no           no      Link-local
192.0.0.0/29         yes     yes   yes          no      DS-Lite
192.0.0.170/31       no      yes   no           no      NAT64/DNS64 discovery
192.0.2.0/24         no      no    no           no      Documentation
192.31.196.0/24      yes     yes   yes          yes     AS112-v4
192.52.193.0/24      yes     yes   yes          yes     AMT
192.175.48.0/24      yes     yes   yes          yes     Direct delegation AS112
198.18.0.0/15        yes     yes   yes          no      Benchmarking
255.255.255.255/32   no      yes   no           no      Limited broadcast`),
  "ref-private-public": ref("Private vs Public IP", `
Private (RFC 1918): 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 — not routed on the internet; reachable only via NAT or VPN.
Public: globally unique, assigned by RIRs (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC) through ISPs.
Also not public: 100.64.0.0/10 (CGNAT), 169.254.0.0/16 (link-local), 127.0.0.0/8 (loopback).
IPv6: ULA fc00::/7 is the private equivalent; global unicast is 2000::/3.
Check any address with the IP Address Type tool.`),
  "ref-cgnat": ref("Carrier-Grade NAT (CGNAT)", `
Range: 100.64.0.0/10 (RFC 6598) — 4,194,304 addresses between the customer CPE and the ISP NAT.
Effect: many customers share one public IPv4; inbound port forwarding and some P2P/gaming break.
Detect: your router's WAN IP is in 100.64.0.0/10, or differs from what "what is my IP" shows.
Workarounds: ask the ISP for a public IP, use IPv6, a VPN/tunnel with a public endpoint, or a reverse proxy/tunnel service.
Don't use 100.64.0.0/10 inside a LAN — it collides with ISP CGNAT and Tailscale.`),
  "ref-link-local": ref("Link-Local / APIPA", `
IPv4 169.254.0.0/16 (RFC 3927): self-assigned when DHCP fails — "APIPA" on Windows. Not routed. 169.254.169.254 is the cloud metadata endpoint on AWS/GCP/Azure/OpenStack.
IPv6 fe80::/10: every IPv6 interface has one; needed for NDP and routing protocols. Use a zone ID (fe80::1%eth0) because the same address can exist on several links.
A 169.254.x.x address on a client usually means: no DHCP server reached, VLAN mismatch, or a cable/Wi-Fi problem.`),
  "ref-multicast": ref("Multicast Addresses", `
IPv4 224.0.0.0/4
224.0.0.1    all hosts          224.0.0.2   all routers
224.0.0.5/6  OSPF               224.0.0.9   RIPv2
224.0.0.18   VRRP               224.0.0.22  IGMPv3
224.0.0.251  mDNS               224.0.0.252 LLMNR
224.0.1.1    NTP                239.255.255.250 SSDP/UPnP
232.0.0.0/8  source-specific    239.0.0.0/8 administratively scoped
IPv6 ff00::/8
ff02::1 all nodes   ff02::2 all routers   ff02::5/6 OSPFv3   ff02::9 RIPng   ff02::fb mDNS   ff02::1:2 DHCPv6 agents   ff02::1:ffXX:XXXX solicited-node
MAC: IPv4 01:00:5e + low 23 bits; IPv6 33:33 + low 32 bits.`),
  "ref-reverse-dns": ref("Reverse DNS", `
IPv4: reverse the octets under in-addr.arpa: 192.0.2.10 → 10.2.0.192.in-addr.arpa PTR host.example.com.
IPv6: reverse every nibble under ip6.arpa: 2001:db8::1 → 1.0.0.0…8.b.d.0.1.0.0.2.ip6.arpa.
Who controls it: the holder of the IP block (your ISP/cloud provider) — set PTRs in their control panel, or get the zone delegated.
Mail servers need matching forward and reverse DNS (FCrDNS): PTR → name, and name → same IP.
Check: dig -x 192.0.2.10 +short  ·  nslookup 192.0.2.10`),
  "ref-reverse-zones": ref("Reverse Zones & Delegation", `
Octet-aligned blocks map to one zone: /8 → a.in-addr.arpa, /16 → b.a.in-addr.arpa, /24 → c.b.a.in-addr.arpa.
Blocks larger than an octet boundary need several zones (a /22 = four /24 zones).
Blocks smaller than /24 use RFC 2317 classless delegation: the parent /24 zone publishes CNAMEs such as
  10.2.0.192.in-addr.arpa. CNAME 10.0-25.2.0.192.in-addr.arpa.
  and delegates 0-25.2.0.192.in-addr.arpa. to the customer's name servers.
IPv6 zones align on nibbles (4 bits): a /48 is 12 nibbles deep, a /56 is 14, a /64 is 16.`),
  "ref-icmp": ref("ICMP Types", `
Type  Name                     Notes
0     Echo Reply               ping reply
3     Destination Unreachable  code 0 net, 1 host, 3 port, 4 frag needed (PMTUD), 13 admin prohibited
5     Redirect
8     Echo Request             ping
9/10  Router Advertisement / Solicitation
11    Time Exceeded            traceroute uses this (code 0 TTL exceeded)
12    Parameter Problem
13/14 Timestamp / Reply
ICMPv6: 1 Dest Unreachable, 2 Packet Too Big (never block — breaks PMTUD), 3 Time Exceeded, 128/129 Echo, 133–137 NDP (RS, RA, NS, NA, Redirect).`),
  "ref-arp-ndp": ref("ARP vs NDP", `
               ARP (IPv4)                     NDP (IPv6)
Layer          own EtherType 0x0806           ICMPv6 types 133–137
Resolution     broadcast who-has              multicast to solicited-node address
Router discovery  —  (DHCP/static)            RS/RA (types 133/134)
Duplicate detection  gratuitous ARP          DAD with NS (type 135)
Cache          arp -a · ip neigh              ip -6 neigh · netsh interface ipv6 show neighbors
Attacks        ARP spoofing                   RA/NS spoofing — mitigate with RA Guard, SEND, DHCPv6 snooping`),
  "ref-asn": ref("Autonomous System Numbers", `
An ASN identifies a network that runs its own BGP routing policy.
16-bit: 1–64495 public · 64496–64511 documentation · 64512–65534 private · 65535 reserved.
32-bit: 65536–4199999999 public (asdot notation e.g. 1.10) · 4200000000–4294967294 private.
Get one from your RIR (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC). Well-known: AS13335 Cloudflare, AS15169 Google, AS16509 Amazon, AS8075 Microsoft, AS47583 Hostinger.
Look one up with the ASN Lookup tool (RDAP).`),
  "ref-wildcard-masks": ref("Wildcard Masks", `
A wildcard mask is the inverse of a subnet mask: 0 bits must match, 1 bits are "don't care".
Subnet mask      Wildcard        Prefix
255.255.255.255  0.0.0.0         /32 (host)
255.255.255.252  0.0.0.3         /30
255.255.255.0    0.0.0.255       /24
255.255.0.0      0.0.255.255     /16
255.0.0.0        0.255.255.255   /8
Cisco ACL: access-list 10 permit 192.168.10.0 0.0.0.255   ·   OSPF: network 10.0.0.0 0.255.255.255 area 0
Non-contiguous wildcards are legal in ACLs (e.g. 0.0.254.255 matches even third octets) but not in routing.`),
  "ref-mtu-mss": ref("MTU & MSS", `
Ethernet MTU 1500 → IPv4 TCP MSS 1460 (−20 IP −20 TCP) · IPv6 TCP MSS 1440 (−40 IPv6 −20 TCP)
PPPoE MTU 1492 → MSS 1452          VXLAN overlay: 1450 inner MTU
WireGuard MTU 1420 (IPv6 outer)    OpenVPN UDP ≈ 1400–1450
GRE adds 24 bytes · IPsec ESP adds ~50–73 · Jumbo frames: 9000
IPv6 minimum link MTU 1280; IPv6 routers never fragment — PMTUD needs ICMPv6 "Packet Too Big".
Symptoms of MTU black holes: small pages load, large transfers hang. Fix with MSS clamping (iptables TCPMSS --clamp-mss-to-pmtu).
Test: ping -M do -s 1472 host (Linux) · ping -f -l 1472 host (Windows).`),
  "tls-cipher-presets": ref("TLS Cipher Presets (Mozilla)", `
MODERN (TLS 1.3 only) — all current browsers
  Protocols: TLSv1.3   Ciphers: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
INTERMEDIATE (recommended for most servers)
  Protocols: TLSv1.2 TLSv1.3
  TLS 1.2 ciphers: ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305
  Curves: X25519, prime256v1, secp384r1   Certificate: ECDSA P-256 or RSA 2048+
OLD (legacy clients only — avoid)
  Adds TLSv1 / TLSv1.1 and CBC ciphers.
nginx: ssl_protocols TLSv1.2 TLSv1.3; ssl_prefer_server_ciphers off;
Traefik: tls.options default: minVersion: VersionTLS12
Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3`),
};

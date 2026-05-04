# reachscan

> Find which IPs are reachable from a constrained network — by comparing scans across multiple operators.

[![Go Version](https://img.shields.io/badge/go-1.21+-00ADD8.svg)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

## What is this?

In networks with **block-by-default** filtering (such as Iran since January 2026, where international internet access is granted only via a government-controlled whitelist), it becomes critical to know which external IPs are actually reachable from inside.

`reachscan` is a small Go binary that probes a list of IPs and reports which ones answer at the TCP layer, and — more importantly — which ones complete a TLS handshake. Running it from multiple networks (e.g. an unfiltered baseline + several Iranian operators) and comparing the results reveals exactly which IPs are on the whitelist.

This is **not** a censorship circumvention tool. It is a measurement tool that tells you *what's reachable*. The data is useful for researchers, system administrators with users in restricted networks, and people setting up legitimate services that need to be accessible from such networks.

## How it works

```
┌─────────────────────────────────────────────────────────────┐
│  1. REQUESTER (you, on an unfiltered network)               │
│                                                             │
│     fetch_ranges.sh   →  prefixes.txt                       │
│     make_targets.py   →  targets.txt  (sampled IPs)         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                          │
                          │  (distribute zip)
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  2. SCANNERS (you + friends, on various networks)           │
│                                                             │
│     scanner.exe                                             │
│     ─ Reads targets.txt                                     │
│     ─ TCP-connects + TLS-handshakes each IP                 │
│     ─ Writes results-<scanner_id>.json                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                          │
                          │  (collect JSONs)
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  3. AGGREGATOR (you, comparing the JSONs)                   │
│                                                             │
│     compare.py                                              │
│     ─ Cross-references all scanners                         │
│     ─ whitelist-universal.txt   (works everywhere)          │
│     ─ blocked-by-iran.txt       (baseline only)             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

The key insight: **a single scan tells you very little**. Two scans from different networks tell you everything.

## Quick start

### For end users (running scanner on Windows)

If someone has sent you a `reachscan-vX.Y.zip`:

1. Extract the zip to your Desktop.
2. Make sure your Iranian internet is connected (Irancell / MCI / TCI). **Do not use VPN.**
3. Double-click `run.bat`.
4. When prompted, type a name like `ali-irancell-tehran` and press Enter.
5. Wait 1–5 minutes.
6. Send the generated `results-XXX.json` file back to whoever asked you.

That's it. The scanner only opens connections to public IPs at port 443 — it doesn't read or send any of your personal data.

### For developers (building from source)

```bash
# 1. Clone
git clone https://github.com/YOUR-USERNAME/reachscan.git
cd reachscan

# 2. Generate target list (one-time, requires curl + jq)
./fetch_ranges.sh                        # default: Hetzner, OVH, Contabo, ...
python3 make_targets.py prefixes.txt     # ~3000 sampled IPs at /22 granularity

# 3. Run locally (Linux/macOS)
go run main.go

# 4. Build distributable Windows zip
./build.sh
# -> dist/reachscan-v1.0.zip
```

## Full workflow (multi-operator comparison)

```bash
# On the requester's machine (e.g. unfiltered network)
./fetch_ranges.sh AS24940              # Hetzner Germany
python3 make_targets.py prefixes.txt   # produces targets.txt

# Run baseline scan from your unfiltered network
go run main.go
# Enter name: starlink-baseline
# -> results-starlink-baseline.json

# Build distribution
./build.sh
# -> send dist/reachscan-v1.0.zip to friends in restricted networks

# Friends run scanner.exe, send back their results-XXX.json files

# Aggregate everything
mkdir reports
mv results-*.json reports/
python3 compare.py reports/ --baseline starlink-baseline

# Output:
# - whitelist-universal.txt  (IPs reachable from everywhere)
# - blocked-by-iran.txt      (IPs only reachable from baseline)
# - per-operator pass rates printed to stdout
```

## File structure

```
reachscan/
├── main.go              Scanner source (Go, ~290 lines)
├── build.sh             Cross-compile to Windows + zip
├── fetch_ranges.sh      Download ASN prefixes from RIPE
├── make_targets.py      CIDR → sampled IP list
├── compare.py           Multi-scanner result comparison
│
├── targets.txt          Generated: list of IPs to scan
├── run.bat              Distributed: Windows entry point
├── README.txt           Distributed: Persian end-user instructions
│
├── README.md            This file
├── LICENSE              MIT
└── .gitignore
```

## Design notes

### Why TCP connect + TLS handshake instead of just ping?

Modern censorship systems often allow ICMP and bare TCP but reject the TLS handshake based on SNI inspection. A successful TLS handshake is the strongest signal that an IP is *truly* usable for the kind of services people care about (HTTPS, V2Ray over TLS, etc.). ICMP success means almost nothing.

### Why sampled (not exhaustive) scanning?

Hetzner alone has ~5 million IPs. Scanning all of them is impractical and noisy. We sample at `/22` granularity (one IP per 1024-host block) to get a representative picture in minutes instead of days. Subnet contiguity means whitelist status is highly correlated within a `/22` — if `116.202.5.10` is whitelisted, `116.202.5.42` almost certainly is too.

### Why Go?

- Single static binary, ~5 MB, no runtime dependencies
- Cross-compile to Windows from any platform with one command
- Goroutines make 500-way concurrent scanning trivial
- Strong stdlib for TCP/TLS — no third-party dependencies needed

### Why no central server?

Files in, files out. No telemetry, no backend, no accounts. Easier to audit, easier to trust, easier to run offline. The aggregation step is just a Python script reading JSON files locally.

## Privacy & security

- **No telemetry.** The scanner never phones home.
- **No personal data.** It reads only `targets.txt` and writes only `results-*.json`.
- **Public IP detection** uses `api.ipify.org` to record which network the scan ran from. This is the only outbound HTTP request beyond the scan targets themselves. You can disable it by deleting `detectPublicIP()` from `main.go`.
- **Output contains:** scanner name (you choose), public IP, timestamps, and the IP-by-IP scan results. No system info, no usernames, no file paths.

## Limitations

- IPv4 only. IPv6 support could be added but Iranian networks barely route IPv6.
- Tests port 443 only. Easy to extend to other ports — see `Config.Port` in `main.go`.
- TLS handshake doesn't validate certificates (`InsecureSkipVerify: true`) because we're connecting by IP, not hostname. This means we can't distinguish a legitimate server from a TLS-terminating middlebox; treat the result as "TLS-reachable" not "HTTPS-valid".
- The comparison logic in `compare.py` requires that every scanner tested every IP. If lists drift between runs, only the intersection is analyzed.

## ‍🇮🇷 راهنمای فارسی (برای کاربر نهایی)

اگه کسی یک فایل zip به اسم `reachscan-vX.Y.zip` برات فرستاده:

1. فایل zip رو روی Desktop باز کن (Extract here)
2. مطمئن شو اینترنت ایرانی وصله (ایرانسل / همراه اول / مخابرات). **VPN خاموش باشه!**
3. روی فایل `run.bat` دوبار کلیک کن
4. وقتی پرسید نام، یه چیزی شبیه این بنویس: `ali-irancell-tehran`
5. بین ۱ تا ۵ دقیقه صبر کن
6. فایلی به اسم `results-XXX.json` تولید می‌شه — اون رو برای کسی که فرستاده برگردون

اگه ویندوز پیغام `Windows protected your PC` داد:
- روی `More info` کلیک کن
- بعد روی `Run anyway`

این برنامه فقط TCP و TLS connect می‌زنه به IP های توی `targets.txt`. هیچ اطلاعاتی از کامپیوتر تو نمی‌خونه و به جایی نمی‌فرسته.

## Contributing

Pull requests welcome. The codebase is small and intentionally so. Before adding features, consider whether they really need to live in the scanner binary or could be a separate tool.

Areas where help is appreciated:
- Additional ASN curation in `fetch_ranges.sh`
- Web-based scanner variant (in-browser, for users who can't run exe)
- Improvements to `compare.py` (HTML report, time-series tracking, etc.)

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

Built in response to the 2026 Iran internet whitelist regime, but useful in any "block-by-default" network. Inspired by the work of [Filterwatch](https://filter.watch), [OONI](https://ooni.org), and [Censored Planet](https://censoredplanet.org).

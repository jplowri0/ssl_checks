# ssl_checker.py — Bulk SSL/TLS Domain Analyser

A zero-dependency Python script that scans a list of domains for SSL/TLS misconfigurations, inspired by [Qualys SSL Labs](https://www.ssllabs.com/ssltest/). Produces colour-coded terminal output, a detailed JSON report, and a summary CSV — useful for security audits, compliance checks, and ongoing infrastructure monitoring.

## Features

### Security Checks

| Category | What's Checked | Severity |
|---|---|---|
| **Deprecated Protocols** | SSLv3, TLS 1.0, TLS 1.1 actively probed via `openssl s_client` (bypasses local library restrictions) | CRITICAL / HIGH |
| **Missing Modern Protocols** | Flags when TLS 1.3 is not supported | MEDIUM |
| **Weak Ciphers** | RC4, DES, 3DES, NULL, EXPORT, anonymous, MD5 MAC | HIGH |
| **CBC on Legacy TLS** | CBC-mode ciphers on TLS 1.0/1.1 (BEAST / Lucky13) | MEDIUM |
| **Certificate Expiry** | Expired certs or expiring within 30 days | CRITICAL / HIGH |
| **Self-Signed Certificates** | Detects when subject matches issuer | HIGH |
| **Hostname Mismatch** | Domain checked against SANs and CN with wildcard support | HIGH |
| **Weak Signature Algorithm** | SHA-1 and MD5 certificate signatures | HIGH / CRITICAL |
| **Weak Key Size** | RSA < 2048 bits, ECC < 256 bits | HIGH |
| **HSTS Missing** | Strict-Transport-Security header absent | MEDIUM |
| **HSTS max-age Too Short** | max-age below 6 months (15768000s) | LOW |
| **No OCSP Stapling** | OCSP stapling not detected | LOW |
| **Cert Verification Failure** | Any certificate chain / trust error | CRITICAL |

### Grading

Each domain receives a simplified letter grade based on finding severity:

| Grade | Criteria |
|---|---|
| **A** | No findings |
| **A-** | LOW findings only |
| **B** | 1 MEDIUM finding |
| **B-** | 2+ MEDIUM findings |
| **C** | 1–2 HIGH findings |
| **D** | 3+ HIGH findings |
| **F** | Any CRITICAL finding |
| **T** | Unreachable / trust failure |

## Requirements

- **Python 3.8+** (uses only the standard library)
- **OpenSSL CLI** (`openssl` binary on `$PATH`)

No `pip install` required. No third-party dependencies.

### Why OpenSSL CLI?

Python's `ssl` module on OpenSSL 3.x refuses to negotiate TLS 1.0/1.1 at the library level, silently masking vulnerable servers. The script shells out to `openssl s_client` with `@SECLEVEL=0` for protocol probing so results reflect what the **server** accepts, not what your local Python build allows.

## Usage

```bash
# Scan domains.csv in the current directory (default)
python3 ssl_checker.py

# Custom input file
python3 ssl_checker.py -f targets.csv

# Custom output prefix, timeout, and parallelism
python3 ssl_checker.py -f targets.csv -o scan_results -t 12 -w 8

# Scan a non-standard port
python3 ssl_checker.py -f targets.csv -p 8443
```

### CLI Options

| Flag | Default | Description |
|---|---|---|
| `-f`, `--file` | `domains.csv` | Input file path |
| `-o`, `--output` | `ssl_report` | Output file prefix (produces `.json` and `.csv`) |
| `-t`, `--timeout` | `8` | Connection timeout in seconds per domain |
| `-w`, `--workers` | `5` | Number of parallel scan threads |
| `-p`, `--port` | `443` | Target port |

## Input Format

The input is flexible — any of these formats work:

### 1. CSV with a `domain` column

The column name is case-insensitive. Extra columns are ignored.

```csv
domain,owner,notes
example.com,ops,production
mail.example.com,infra,legacy
```

### 2. CSV without a `domain` column

The first column is used automatically. A note is printed to stderr telling you which column was picked.

```csv
target,environment
example.com,prod
staging.example.com,staging
```

### 3. Plain text — one domain per line

```
example.com
https://mail.example.com/path
# comments are skipped
old.example.com:8443
```

In all cases the script strips `http://`/`https://` prefixes, URL paths, and port suffixes automatically.

## Output

### Terminal

Colour-coded per-domain results with a summary table:

```
════════════════════════════════════════════════════════════════════════
  example.com:443   →   Grade: A-
════════════════════════════════════════════════════════════════════════
  IP Address       : 93.184.216.34
  Subject CN       : example.com
  Issuer           : DigiCert
  Valid Until      : Jun 15 12:00:00 2025 GMT  (84 days remaining)
  ...
  Protocols        : TLSv1.2, TLSv1.3
  HSTS             : Yes — max-age=31536000
  OCSP Stapling    : No

  ────────────────────────────────────────────────────────────────
  FINDINGS (1):
    [LOW] No OCSP Stapling
           OCSP stapling not detected. Enabling it improves privacy and performance.
```

### JSON Report (`ssl_report.json`)

Full structured data for every domain — certificate details, supported protocols, negotiated ciphers, and all findings with severity. Useful for ingesting into SIEMs, dashboards, or further automation.

### CSV Report (`ssl_report.csv`)

One row per domain with key fields and finding counts — ready to drop into a spreadsheet or share with stakeholders. Columns include:

`domain`, `grade`, `days_until_expiry`, `protocols_supported`, `self_signed`, `hsts_present`, `finding_count`, `critical_count`, `high_count`, `medium_count`, `findings_summary`

## Examples

### Quick audit of your infrastructure

```bash
echo "example.com
mail.example.com
vpn.example.com" > domains.csv

python3 ssl_checker.py
```

### CI/CD compliance gate

```bash
python3 ssl_checker.py -f production_domains.csv -o ci_report

# Fail the pipeline if any domain scores below B
python3 -c "
import json, sys
data = json.load(open('ci_report.json'))
bad = [d['domain'] for d in data if d['grade'] in ('C','D','F','T')]
if bad:
    print(f'FAIL: {bad}')
    sys.exit(1)
print('PASS: all domains B or above')
"
```

### Feed results into a SIEM

The JSON output can be shipped directly to Wazuh, Splunk, Elastic, or any log pipeline:

```bash
python3 ssl_checker.py -f domains.csv -o /var/log/ssl_audit
# Then ingest ssl_audit.json via your SIEM's file input
```

## Limitations

- **Not a full SSL Labs replacement** — does not test for every vulnerability (e.g., Heartbleed, ROBOT, Ticketbleed require active exploitation probes). This tool focuses on configuration-level issues detectable via standard TLS handshakes.
- **Single cipher per protocol** — the script captures the cipher the server *negotiates* for each TLS version, not the full list of offered cipher suites. A server may support additional weak ciphers that only appear when specific client cipher lists are sent.
- **OCSP stapling detection** — relies on `openssl s_client -status` which can produce false negatives depending on server/CDN behaviour.
- **Rate limiting** — hammering many domains in parallel with high worker counts may trigger rate limits or IDS alerts. Adjust `--workers` and `--timeout` accordingly.

## Licence

Do what you want with it.

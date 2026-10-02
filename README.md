# pentrix-cve

![Python](https://img.shields.io/badge/python-3.6%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Deps](https://img.shields.io/badge/deps-zero-brightgreen)

A tiny CVE lookup CLI powered by the NVD API 2.0. Zero dependencies, just the Python standard library.

## Features

- Look up any CVE by exact ID (e.g. `CVE-2021-44228`)
- Keyword search across the NVD with a configurable result limit
- Shows CVSS v3.x base score and severity, falling back to v2 when v3 is missing
- Clean human-readable cards, or machine-readable `--json` output
- Polite API behavior: 6-second delay between paged requests, clear messages on HTTP 403/429

## Install

```bash
git clone https://github.com/mizazhaider-ceh/pentrix-cve.git
cd pentrix-cve
python3 cve.py --help
```

Requirements: Python 3.6+. No pip packages, no virtualenv, nothing.

## Usage

### Look up one CVE by ID

```bash
python3 cve.py --id CVE-2021-44228
```

```
================================================================
CVE ID     : CVE-2021-44228
Severity   : CRITICAL (10.0, CVSS v3.1)
Published  : 2021-12-10
References : 103
----------------------------------------------------------------
Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log...
================================================================
```

### Keyword search

```bash
python3 cve.py --search "apache log4j" --limit 3
```

```
================================================================
CVE ID     : CVE-2012-5616
Severity   : LOW (1.5, CVSS v2.0)
Published  : 2013-01-22
References : 24
----------------------------------------------------------------
Apache CloudStack 4.0.0-incubating and Citrix CloudPlatform (formerly Citrix CloudStack) before 3.0.6 stores sensitive information in the log4j.conf log file, which allows local users to obtain (1) the SSH private key as recorded by the createSSHKeyPair API, (2) the password of...
================================================================
================================================================
CVE ID     : CVE-2017-5645
Severity   : CRITICAL (9.8, CVSS v3.1)
Published  : 2017-04-17
References : 164
----------------------------------------------------------------
In Apache Log4j 2.x before 2.8.2, when using the TCP socket server or UDP socket server to receive serialized log events from another application, a specially crafted binary payload can be sent that, when deserialized, can execute arbitrary code.
================================================================
...
```

### JSON output (for piping into jq or your own tooling)

```bash
python3 cve.py --id CVE-2021-44228 --json
```

```json
{
  "id": "CVE-2021-44228",
  "cvss_version": "3.1",
  "cvss_score": 10.0,
  "severity": "CRITICAL",
  "published": "2021-12-10",
  "description": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log...",
  "references": 103
}
```

### Options

| Flag | Description |
|---|---|
| `--id CVE-ID` | Look up one CVE by exact ID |
| `--search KEYWORD` | Keyword search |
| `--limit N` | Max search results (default: 5) |
| `--timeout SECONDS` | HTTP timeout per request (default: 15) |
| `--json` | Print JSON instead of cards |

Exit codes: `0` on success, `1` on lookup/network/API errors, `2` on bad CLI usage.

## Rate limits and data source

All data comes from the [NVD API 2.0](https://nvd.nist.gov/developers), maintained by NIST. Keyless requests are rate-limited by NIST (a few per 30 seconds), so:

- `pentrix-cve` waits 6 seconds between paged requests automatically.
- If you hit HTTP 403/429, wait a few minutes and retry. For heavy use, request a free API key at https://nvd.nist.gov/developers/request-an-api-key.

## License

MIT, see [LICENSE](LICENSE).

# Email

![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/leansecurity-co/email?utm_source=oss&utm_medium=github&utm_campaign=leansecurity-co%2Femail&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)

A Golang tool for analyzing email security authentication headers (SPF, DKIM, DMARC, and ARC) from `.msg` and `.eml` files, plus DMARC aggregate report analysis with forensic capabilities.

## Features

### Email Analysis

- Parse `.msg` (Microsoft Outlook) and `.eml` (RFC822) files
- Analyze SPF, DKIM, DMARC, and ARC authentication results
- Extract Microsoft Spam Confidence Level (SCL) scores
- Output results in human-readable text or JSON format
- Verbose mode to include all raw email headers

### DMARC Aggregate Report Analysis

- Parse DMARC aggregate reports (RFC 7489) from XML, GZIP, or ZIP files
- Full forensic analysis with threat scoring (0-100 scale)
- IP geolocation enrichment with GeoIP2 (optional, graceful degradation)
- ASN and organization identification (requires separate ASN database)
- Output in Text, JSON, or Markdown format
- Actionable recommendations based on findings

## Installation

Requires Go 1.20 or later.

```bash
go install github.com/leansecurity-co/email@latest
```

To uninstall:

```bash
rm $(go env GOPATH)/bin/email
```

Or build from source:

```bash
git clone https://github.com/leansecurity-co/email.git
cd email
go build -o email main.go
```

## Usage

### Analyzing Email Files

```bash
./email [-v] [-json] <email-file>

Options:
  -v       Verbose output (include all raw headers)
  -json    Output results as JSON

Examples:
  ./email sample.msg
  ./email sample.eml
  ./email -v sample.msg
  ./email -json sample.eml > results.json
```

### Analyzing DMARC Reports

```bash
./email dmarc [-v] [-json] [-md] [-no-enrich] [-geoip-db <path>] <report-file>

Options:
  -v              Verbose output (include raw XML)
  -json           Output results as JSON
  -md             Output results as Markdown
  -no-enrich      Skip IP geolocation enrichment
  -geoip-db       Path to GeoIP2 City database (.mmdb)

Supported formats: .xml, .xml.gz, .zip

Examples:
  ./email dmarc report.xml
  ./email dmarc -json report.xml.gz > analysis.json
  ./email dmarc -md report.zip > report.md
  ./email dmarc -v -geoip-db /path/to/GeoLite2-City.mmdb report.xml
```

### GeoIP Database Setup

For IP geolocation enrichment, download MaxMind's free GeoLite2 databases:

1. **GeoLite2-City.mmdb** - Provides country, city location
2. **GeoLite2-ASN.mmdb** - Provides ASN and organization (optional)

Place them in the current directory, `./data/`, `/usr/share/GeoIP/`, or set paths via environment variables:

```bash
export GEOIP_DB_PATH=/path/to/GeoLite2-City.mmdb
export GEOIP_ASN_DB_PATH=/path/to/GeoLite2-ASN.mmdb
```

If no databases are found, the tool continues without geolocation (graceful degradation).

## Authentication Results

### SPF (Sender Policy Framework)

Validates that the sending mail server is authorized by the domain.

Results: `pass`, `fail`, `softfail`, `neutral`, `none`, `temperror`, `permerror`

### DKIM (DomainKeys Identified Mail)

Verifies cryptographic signatures to ensure email hasn't been tampered with.

Results: `pass`, `fail`, `neutral`, `temperror`, `permerror`, `none`

### DMARC (Domain-based Message Authentication, Reporting & Conformance)

Enforces SPF and DKIM alignment and specifies handling policy.

Results: `pass`, `fail`, `none`

Policies: `none`, `quarantine`, `reject`

### ARC (Authenticated Received Chain)

Preserves authentication results across email forwarding intermediaries.

Results: `pass`, `fail`, `none`

## Example Output

### Text Output

```text
================================================================================
EMAIL SECURITY ANALYSIS REPORT
================================================================================

EMAIL INFORMATION
--------------------------------------------------------------------------------
From:       "Example Company" <sender@example.com>
Subject:    Sample Email Subject

SPF (SENDER POLICY FRAMEWORK) RESULTS
--------------------------------------------------------------------------------
SPF Check #1:
  Result:     PASS ✓
  Domain:     example.com

DKIM (DOMAINKEYS IDENTIFIED MAIL) RESULTS
--------------------------------------------------------------------------------
DKIM Signature #1:
  Result:     PASS ✓
  Domain:     example.com

DMARC (DOMAIN MESSAGE AUTHENTICATION REPORTING & CONFORMANCE) RESULTS
--------------------------------------------------------------------------------
DMARC Check #1:
  Result:     PASS ✓
  Domain:     example.com

SECURITY SUMMARY
--------------------------------------------------------------------------------
SPF Authentication:   PASS ✓
DKIM Authentication:  PASS ✓
DMARC Authentication: PASS ✓

Overall Assessment: SECURE ✓
================================================================================
```

### JSON Output

```json
{
  "from": "\"Example Company\" <sender@example.com>",
  "subject": "Sample Email Subject",
  "spf_results": [{ "result": "pass", "domain": "example.com" }],
  "dkim_results": [{ "result": "pass", "domain": "example.com", "selector": "s1" }],
  "dmarc_results": [{ "result": "pass", "domain": "example.com" }]
}
```

### DMARC Report Text Output

```text
================================================================================
DMARC AGGREGATE REPORT ANALYSIS
================================================================================

REPORT INFORMATION
--------------------------------------------------------------------------------
Organization:   google.com
Report ID:      5113521678212323448
Email Contact:  noreply-dmarc-support@google.com
Report Period:  2025-12-27 00:00:00 to 2025-12-28 23:59:59
Domain:         example.com
Policy:         quarantine | Subdomain: quarantine | Percentage: 100%
Alignment:      DKIM: relaxed | SPF: relaxed

AUTHENTICATION SUMMARY
--------------------------------------------------------------------------------
Total Emails:         3
Overall Pass Rate:    100.0% ✓
SPF Pass Rate:        100.0% ✓
DKIM Pass Rate:       100.0% ✓

DISPOSITION BREAKDOWN
--------------------------------------------------------------------------------
none:                 3 (100.0%)

THREAT ASSESSMENT
--------------------------------------------------------------------------------
Overall Threat Level: LOW ✓

RECOMMENDATIONS
--------------------------------------------------------------------------------
• Consider upgrading to stricter DMARC policy
================================================================================
```

## How It Works

The tool extracts RFC822 headers from email files and parses authentication headers:

- `.eml` files: Read directly (already RFC822 format)
- `.msg` files: Extract headers from Microsoft CFBF/OLE binary format using ZIP extraction or binary pattern matching

Parsed headers include: `Received-SPF`, `DKIM-Signature`, `Authentication-Results`, `ARC-Authentication-Results`, and standard email headers.

## Limitations

- Parses existing authentication results only (doesn't perform live cryptographic verification)
- `.msg` files must contain RFC822 headers (some may only have MAPI properties)
- Results reflect the receiving server's evaluation at time of receipt

## License

Apache License 2.0 - see [LICENSE](LICENSE) file for details.

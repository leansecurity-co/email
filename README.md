# Email Watch

A Golang tool for analyzing email security authentication headers (SPF, DKIM, DMARC, and ARC) from `.msg` and `.eml` files.

## Features

- Parse `.msg` (Microsoft Outlook) and `.eml` (RFC822) files
- Analyze SPF, DKIM, DMARC, and ARC authentication results
- Extract Microsoft Spam Confidence Level (SCL) scores
- Output results in human-readable text or JSON format
- Verbose mode to include all raw email headers

## Installation

Requires Go 1.20 or later.

```bash
# Build the binary
go build -o email-watch main.go

# Or install to $GOPATH/bin
go install
```

## Usage

```bash
./email-watch [-v] [-json] <email-file>

Options:
  -v       Verbose output (include all raw headers)
  -json    Output results as JSON

Examples:
  ./email-watch sample.msg
  ./email-watch sample.eml
  ./email-watch -v sample.msg
  ./email-watch -json sample.eml > results.json
```

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

MIT License - see [LICENSE](LICENSE) file for details.

# Email Watch

A production-ready Golang tool for parsing Microsoft Outlook `.msg` files and extracting email security authentication headers (SPF, DKIM, DMARC, and ARC).

## Features

- **Parse .msg files**: Extracts RFC822 email headers from Microsoft Outlook message format (CDFV2)
- **SPF Analysis**: Validates Sender Policy Framework authentication results
- **DKIM Validation**: Examines DomainKeys Identified Mail signatures and verification status
- **DMARC Evaluation**: Checks Domain-based Message Authentication, Reporting & Conformance alignment
- **ARC Support**: Analyzes Authenticated Received Chain for email forwarding scenarios
- **Multiple Output Formats**: Human-readable text or structured JSON
- **Comprehensive Error Handling**: Graceful handling of malformed or incomplete data
- **Verbose Mode**: Option to include all raw email headers

## Installation

### Prerequisites

- Go 1.20 or later

### Build from Source

```bash
# Clone or navigate to the repository
cd /Users/charlesgreen/go/src/github.com/charlesgreen/email-watch

# Download dependencies
go mod download

# Build the binary
go build -o email-watch main.go

# Optional: Install to your Go bin directory
go install
```

## Usage

### Basic Usage

```bash
./email-watch sample-email.msg
```

### Command-Line Options

```bash
./email-watch [-v] [-json] <msg-file>

Options:
  -v       Verbose output (include all raw headers)
  -json    Output results as JSON

Examples:
  ./email-watch sample-email.msg
  ./email-watch -v sample-email.msg
  ./email-watch -json sample-email.msg > results.json
```

## Understanding Email Security Headers

### SPF (Sender Policy Framework)

SPF validates that the sending mail server is authorized to send email on behalf of the domain. It checks the sender's IP address against the domain's SPF record published in DNS.

**Possible Results:**
- `pass` - The sender IP is authorized
- `fail` - The sender IP is not authorized
- `softfail` - The sender IP is not authorized, but the domain is in transition
- `neutral` - The domain makes no assertion about authorization
- `none` - No SPF record exists
- `temperror` - Temporary error during lookup
- `permerror` - Permanent error (malformed SPF record)

### DKIM (DomainKeys Identified Mail)

DKIM uses cryptographic signatures to verify that an email hasn't been tampered with in transit and confirms the sender's domain identity.

**Possible Results:**
- `pass` - Signature is valid
- `fail` - Signature is invalid
- `neutral` - Signature couldn't be verified
- `temperror` - Temporary error during verification
- `permerror` - Permanent error (malformed signature)
- `none` - No DKIM signature present

**Key Components:**
- `d=` - Signing domain
- `s=` - Selector (identifies the specific DKIM key)
- `a=` - Algorithm (typically rsa-sha256)

### DMARC (Domain-based Message Authentication, Reporting & Conformance)

DMARC builds on SPF and DKIM to specify how receivers should handle authentication failures. It also provides a mechanism for domain owners to receive reports about email authentication.

**Possible Results:**
- `pass` - Email passed DMARC alignment checks
- `fail` - Email failed DMARC alignment
- `none` - No DMARC policy exists

**Policies:**
- `none` - Monitor only, no action taken on failures
- `quarantine` - Treat suspicious email as spam
- `reject` - Reject email that fails authentication

### ARC (Authenticated Received Chain)

ARC preserves authentication results when email is forwarded through intermediaries (like mailing lists). It creates a chain of custody that maintains authentication across hops.

**Chain Results:**
- `pass` - Chain is intact and valid
- `fail` - Chain is broken
- `none` - No ARC headers present

## Example Output

### Text Output

```
================================================================================
EMAIL SECURITY ANALYSIS REPORT
================================================================================

EMAIL INFORMATION
--------------------------------------------------------------------------------
From:       "Example Company" <sender@example.com>
To:         recipient@example.com
Subject:    Sample Email Subject
Date:       Wed, 12 Nov 2025 08:01:22 +0000 (UTC)
Message-ID: <sample-message-id@mail.example.com>

SPF (SENDER POLICY FRAMEWORK) RESULTS
--------------------------------------------------------------------------------
SPF validates that the sending server is authorized to send email for the domain.

SPF Check #1:
  Result:     PASS ✓
  Client IP:  167.89.59.64

SPF Check #2:
  Result:     PASS ✓
  Domain:     mail.example.com

DKIM (DOMAINKEYS IDENTIFIED MAIL) RESULTS
--------------------------------------------------------------------------------
DKIM uses cryptographic signatures to verify email authenticity and integrity.

DKIM Signature #1:
  Result:     PASS ✓
  Domain:     example.com
  Selector:   s1
  Algorithm:  rsa-sha256

DMARC (DOMAIN MESSAGE AUTHENTICATION REPORTING & CONFORMANCE) RESULTS
--------------------------------------------------------------------------------
DMARC builds on SPF and DKIM to specify how to handle authentication failures.

DMARC Check #1:
  Result:      PASS ✓
  Domain:      example.com
  Disposition: none

ARC (AUTHENTICATED RECEIVED CHAIN) RESULTS
--------------------------------------------------------------------------------
ARC preserves authentication results across email forwarding.

ARC Chain #1:
  Result:   PASS ✓
  Chain:    PASS ✓

SECURITY SUMMARY
--------------------------------------------------------------------------------
SPF Authentication:   PASS ✓
DKIM Authentication:  PASS ✓
DMARC Authentication: PASS ✓

Overall Assessment: SECURE ✓
This email passed all major authentication checks.

================================================================================
```

### JSON Output

```json
{
  "from": "\"Example Company\" <sender@example.com>",
  "to": "recipient@example.com",
  "subject": "Sample Email Subject",
  "date": "Wed, 12 Nov 2025 08:01:22 +0000 (UTC)",
  "message_id": "<sample-message-id@mail.example.com>",
  "spf_results": [
    {
      "result": "pass",
      "domain": "mail.example.com",
      "explanation": "sender IP is 192.0.2.1",
      "client_ip": "192.0.2.1"
    }
  ],
  "dkim_results": [
    {
      "result": "pass",
      "domain": "example.com",
      "selector": "s1",
      "header_d": "example.com",
      "header_s": "s1",
      "header_a": "rsa-sha256"
    }
  ],
  "dmarc_results": [
    {
      "result": "pass",
      "policy": "",
      "disposition": "none",
      "domain": "example.com"
    }
  ],
  "arc_results": [
    {
      "instance": 0,
      "result": "pass",
      "chain": "pass"
    }
  ]
}
```

## Architecture

### MSG File Parsing

The tool uses a multi-strategy approach to extract RFC822 headers from Microsoft Outlook `.msg` files:

1. **ZIP-based extraction**: Attempts to open the file as a ZIP archive (some MSG formats)
2. **Binary pattern matching**: Searches for RFC822 header patterns in the CFBF structure
3. **Header reconstruction**: Extracts and validates email headers from the binary data

### Security Header Extraction

The tool parses the following headers:

- `Received-SPF`: SPF authentication results
- `DKIM-Signature`: DKIM signature information
- `Authentication-Results`: Comprehensive authentication results from mail servers
- `ARC-Authentication-Results`: ARC chain information
- Standard email headers: `From`, `To`, `Subject`, `Date`, `Message-ID`

## Dependencies

```go
require (
    github.com/emersion/go-message v0.18.1      // RFC822 email parsing
    github.com/rotisserie/eris v0.5.4            // Enhanced error handling
    github.com/yeka/zip v0.0.0-20231116150916   // ZIP archive support
)
```

## Technical Details

### Supported MSG Format

- Microsoft Outlook Message format (.msg)
- CDFV2 (Compound Document File V2)
- OLE/CFBF (Object Linking and Embedding / Compound File Binary Format)

### Header Parsing Strategy

The tool implements RFC-compliant parsing for:
- Authentication-Results header (RFC 8601)
- SPF results (RFC 7208)
- DKIM signatures (RFC 6376)
- DMARC policy (RFC 7489)
- ARC chain (RFC 8617)

### Error Handling

The tool uses the `eris` library for enhanced error handling with stack traces. All errors are wrapped with context to aid in debugging.

## Limitations

- Only parses existing authentication results from headers (doesn't perform live SPF/DKIM/DMARC verification)
- Requires that the MSG file contains RFC822 headers (some MSG files may only have MAPI properties)
- Authentication results reflect the receiving server's evaluation at the time of receipt

## Use Cases

1. **Email Forensics**: Analyze suspicious emails for authentication failures
2. **Deliverability Debugging**: Understand why emails may have been rejected or marked as spam
3. **Security Auditing**: Batch analysis of email authentication compliance
4. **Threat Intelligence**: Extract authentication data from phishing samples
5. **Email System Testing**: Validate that your email infrastructure properly authenticates messages

## Security Considerations

This tool is designed for **analysis only**. It:
- Does NOT validate or verify signatures cryptographically
- Does NOT perform DNS lookups for SPF/DMARC records
- Does NOT execute any email content
- Only extracts and displays authentication results from headers

For live email authentication, use dedicated mail server software or online verification tools.

## Contributing

When contributing, please ensure:
- Code follows Go best practices and idioms
- All functions include comprehensive comments
- Error handling uses the `eris` library for context
- New features include appropriate test coverage

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Charles Green

## Acknowledgments

- Microsoft Outlook MSG format documentation
- RFC 7208 (SPF)
- RFC 6376 (DKIM)
- RFC 7489 (DMARC)
- RFC 8617 (ARC)
- RFC 8601 (Authentication-Results)

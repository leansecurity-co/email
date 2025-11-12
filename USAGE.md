# Email Watch - Quick Start Guide

## Quick Test

```bash
# Run on the sample file
./email-watch sample-email.msg
```

## Common Use Cases

### 1. Basic Analysis

Analyze a single .msg file:

```bash
./email-watch suspicious-email.msg
```

### 2. Detailed Analysis with All Headers

Include all raw email headers in the output:

```bash
./email-watch -v phishing-sample.msg
```

### 3. Export to JSON for Processing

Export results as JSON for integration with other tools:

```bash
./email-watch -json sample-email.msg > results.json
```

### 4. Batch Processing

Process multiple files and save results:

```bash
for file in emails/*.msg; do
    echo "Processing: $file"
    ./email-watch -json "$file" > "results/$(basename "$file" .msg).json"
done
```

### 5. Quick Security Check

Check if an email passed all security checks:

```bash
./email-watch email.msg | grep "Overall Assessment"
```

### 6. Extract Specific Information

Extract SPF results only:

```bash
./email-watch -json email.msg | jq '.spf_results'
```

Extract DKIM information:

```bash
./email-watch -json email.msg | jq '.dkim_results'
```

## Interpreting Results

### Security Status Indicators

- **✓ (Check mark)**: Test passed
- **✗ (X mark)**: Test failed
- **⚠ (Warning)**: Soft fail or inconclusive
- **~ (Tilde)**: Neutral result
- **○ (Circle)**: Not found/none

### Overall Assessment

The tool provides three levels of assessment:

1. **SECURE ✓**: All authentication checks passed (SPF, DKIM, DMARC)
2. **PARTIALLY SECURE ⚠**: Some checks passed, but not all
3. **INSECURE ✗**: Failed authentication checks

### What Each Result Means

#### SPF Results

- **PASS**: The sending server is authorized to send email for this domain
- **FAIL**: The sending server is NOT authorized (potential spoofing)
- **SOFTFAIL**: Not authorized but policy is lenient
- **NEUTRAL**: Domain makes no assertion
- **NONE**: No SPF record found

#### DKIM Results

- **PASS**: Email signature is valid and hasn't been tampered with
- **FAIL**: Signature is invalid or message was modified
- **NONE**: No DKIM signature present

#### DMARC Results

- **PASS**: Email aligns with DMARC policy
- **FAIL**: Email fails alignment checks
- **NONE**: No DMARC policy found

## Troubleshooting

### "Could not find RFC822 email headers"

The .msg file may be corrupted or use an unsupported format. Try:
1. Re-export the email from Outlook
2. Save as .eml instead of .msg if possible

### "Failed to parse email message"

The extracted headers may be malformed. Try:
1. Use verbose mode to see what was extracted: `./email-watch -v file.msg`
2. Check if the file is actually a .msg file: `file your-email.msg`

### No Authentication Results

Some emails legitimately don't have authentication headers:
- Internal emails
- Emails from systems that don't implement SPF/DKIM
- Very old emails

This is expected and the tool will report "No SPF/DKIM/DMARC results found"

## Integration Examples

### Python Integration

```python
import subprocess
import json

def analyze_email(msg_file):
    result = subprocess.run(
        ['./email-watch', '-json', msg_file],
        capture_output=True,
        text=True
    )
    return json.loads(result.stdout)

# Use it
report = analyze_email('sample.msg')
print(f"SPF Status: {report['spf_results'][0]['result']}")
print(f"DKIM Status: {report['dkim_results'][0]['result']}")
```

### Shell Script Integration

```bash
#!/bin/bash

# Analyze all .msg files in a directory
for msg_file in *.msg; do
    echo "=== Analyzing: $msg_file ==="

    # Get overall security status
    assessment=$(./email-watch "$msg_file" | grep "Overall Assessment")

    if echo "$assessment" | grep -q "SECURE"; then
        echo "✓ Safe"
    elif echo "$assessment" | grep -q "INSECURE"; then
        echo "✗ Suspicious - requires manual review"
        mv "$msg_file" suspicious/
    else
        echo "⚠ Partial - requires review"
        mv "$msg_file" review/
    fi
done
```

### JSON Analysis with jq

```bash
# Count how many emails passed DMARC
./email-watch -json *.msg | jq '.dmarc_results[] | select(.result=="pass")' | wc -l

# Extract all sender domains
./email-watch -json *.msg | jq -r '.from' | sed 's/.*<\(.*\)>/\1/' | cut -d@ -f2 | sort -u

# Find emails that failed SPF
./email-watch -json *.msg | jq 'select(.spf_results[].result=="fail")'
```

## Best Practices

1. **Always check authentication results**: Don't rely solely on the "From" address
2. **Understand the context**: Internal emails may not have all authentication headers
3. **Verify suspicious emails**: Use verbose mode to see all details
4. **Combine with other tools**: This tool shows what the receiving server saw, not live verification
5. **Archive results**: Save JSON output for audit trails

## Advanced Usage

### Compare Multiple Emails

```bash
# Compare SPF results across multiple emails
for file in *.msg; do
    echo -n "$file: "
    ./email-watch -json "$file" | jq -r '.spf_results[0].result'
done
```

### Generate Summary Report

```bash
#!/bin/bash

total=0
secure=0
partial=0
insecure=0

for file in *.msg; do
    ((total++))
    assessment=$(./email-watch "$file" | grep "Overall Assessment")

    if echo "$assessment" | grep -q "SECURE"; then
        ((secure++))
    elif echo "$assessment" | grep -q "PARTIALLY"; then
        ((partial++))
    else
        ((insecure++))
    fi
done

echo "=== Email Security Summary ==="
echo "Total analyzed: $total"
echo "Secure: $secure ($((secure * 100 / total))%)"
echo "Partial: $partial ($((partial * 100 / total))%)"
echo "Insecure: $insecure ($((insecure * 100 / total))%)"
```

## Support

For issues or questions:
1. Check that your .msg file is valid: `file your-email.msg`
2. Try verbose mode to see what's being extracted: `./email-watch -v your-email.msg`
3. Verify the file contains email headers: `strings your-email.msg | grep "From:"`

## See Also

- [README.md](README.md) - Full documentation
- [RFC 7208](https://tools.ietf.org/html/rfc7208) - SPF specification
- [RFC 6376](https://tools.ietf.org/html/rfc6376) - DKIM specification
- [RFC 7489](https://tools.ietf.org/html/rfc7489) - DMARC specification

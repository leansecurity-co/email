# Email - Usage Guide

## Quick Start

```bash
./email sample.msg
./email sample.eml
```

## Common Use Cases

### Basic Analysis

```bash
./email suspicious-email.msg
./email phishing-sample.eml
```

### Detailed Analysis with All Headers

```bash
./email -v sample.msg
```

### Export to JSON

```bash
./email -json sample.eml > results.json
```

### Batch Processing

```bash
for file in emails/*.{msg,eml}; do
    ./email -json "$file" > "results/$(basename "$file" | cut -d. -f1).json"
done
```

### Quick Security Check

```bash
./email email.msg | grep "Overall Assessment"
```

### Extract Specific Information

```bash
./email -json email.msg | jq '.spf_results'
./email -json email.eml | jq '.dkim_results'
```

## Interpreting Results

### Status Indicators

- `✓` - Test passed
- `✗` - Test failed
- `⚠` - Soft fail or inconclusive
- `~` - Neutral result
- `○` - Not found/none

### Overall Assessment

- **SECURE**: All authentication checks passed (SPF, DKIM, DMARC)
- **PARTIALLY SECURE**: Some checks passed
- **INSECURE**: Failed authentication checks

## Troubleshooting

### "Could not find RFC822 email headers"

The file may be corrupted or use an unsupported format. Try re-exporting from Outlook or saving as `.eml` instead.

### "Failed to parse email message"

Use verbose mode to see extracted headers: `./email -v file.msg`

### No Authentication Results

Internal emails and emails from legacy systems may not have authentication headers. This is normal.

## Integration Examples

### Python

```python
import subprocess
import json

result = subprocess.run(['./email', '-json', 'sample.msg'],
                       capture_output=True, text=True)
report = json.loads(result.stdout)
print(f"SPF: {report['spf_results'][0]['result']}")
```

### Shell Script

```bash
for file in emails/*.{msg,eml}; do
    assessment=$(./email "$file" | grep "Overall Assessment")
    if echo "$assessment" | grep -q "SECURE"; then
        echo "✓ $file: Safe"
    else
        echo "✗ $file: Suspicious"
    fi
done
```

### JSON Analysis with jq

```bash
# Find emails that failed SPF
./email -json sample.msg | jq 'select(.spf_results[].result=="fail")'

# Extract sender domains
./email -json sample.eml | jq -r '.from' | grep -oE '[^@]+@[^>]+'
```

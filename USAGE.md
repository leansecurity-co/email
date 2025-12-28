# Email - Usage Guide

## Quick Start

### Email Analysis

```bash
./email sample.msg
./email sample.eml
```

### DMARC Report Analysis

```bash
./email dmarc report.xml
./email dmarc -json report.xml.gz
./email dmarc -md report.zip
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

## DMARC Report Use Cases

### Analyze a DMARC Report

```bash
# Basic text output
./email dmarc report.xml

# JSON output for automation
./email dmarc -json report.xml > analysis.json

# Markdown for documentation
./email dmarc -md report.xml > report.md
```

### Compressed Reports

DMARC reports from email providers typically arrive as compressed files:

```bash
# GZIP compressed (common from Google, Microsoft)
./email dmarc google.com!example.com!1234567890!1234567899.xml.gz

# ZIP archives
./email dmarc yahoo.com!example.com!1234567890.zip
```

### Batch DMARC Processing

```bash
# Process all DMARC reports in a directory
for file in dmarc-reports/*.{xml,xml.gz,zip}; do
    echo "Processing: $file"
    ./email dmarc -json "$file" > "results/$(basename "$file" .xml).json" 2>/dev/null
done
```

### DMARC Report with GeoIP Enrichment

```bash
# With custom GeoIP database path
./email dmarc -geoip-db /usr/share/GeoIP/GeoLite2-City.mmdb report.xml

# Skip enrichment for faster processing
./email dmarc -no-enrich report.xml
```

### Extract Specific DMARC Information

```bash
# Get threat level
./email dmarc -json report.xml | jq '.analysis.overall_threat_level'

# List failing sources
./email dmarc -json report.xml | jq '.analysis.failing_sources[]'

# Get recommendations
./email dmarc -json report.xml | jq '.analysis.recommendations[].message'

# Extract unique source IPs
./email dmarc -json report.xml | jq -r '.records[].row.source_ip' | sort -u
```

### DMARC Monitoring Script

```bash
#!/bin/bash
# Monitor DMARC reports for high-threat sources

for report in /var/mail/dmarc/*.xml; do
    threat=$(./email dmarc -json "$report" | jq -r '.analysis.overall_threat_level')
    if [ "$threat" = "high" ] || [ "$threat" = "critical" ]; then
        echo "ALERT: High threat detected in $report"
        ./email dmarc "$report"
    fi
done
```

### SIEM Integration

```bash
# Output DMARC analysis as JSON for log ingestion
./email dmarc -json report.xml | \
    jq -c '{
        timestamp: .metadata.date_range.begin,
        org: .metadata.org_name,
        domain: .policy_published.domain,
        threat_level: .analysis.overall_threat_level,
        pass_rate: .analysis.pass_rate,
        failing_ips: [.analysis.failing_sources[].source_ip]
    }'
```

## Interpreting DMARC Results

### Threat Levels

| Level | Score | Description |
|-------|-------|-------------|
| Low | 0-29 | All authentication passes, normal volume |
| Medium | 30-49 | Single auth failure or minor anomaly |
| High | 50-69 | Multiple failures, volume anomaly |
| Critical | 70-100 | Abuse indicators, immediate review needed |

### Common Recommendations

- **Upgrade DMARC policy**: Move from `none` to `quarantine` or `reject`
- **Review failing sources**: Investigate unauthorized senders
- **Check DKIM alignment**: Ensure DKIM domains match header domain
- **Monitor SPF includes**: Verify all legitimate senders are included

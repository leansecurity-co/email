package main

import (
	"fmt"
	"net/mail"
	"strings"
	"testing"
)

// TestParseSCLHeader tests the parseSCLHeader function with various SCL values
func TestParseSCLHeader(t *testing.T) {
	tests := []struct {
		name          string
		header        string
		headerSource  string
		expectedScore int
		expectedDesc  string
		expectNil     bool
	}{
		{
			name:          "SCL -1 (skipped filtering)",
			header:        "CIP:255.255.255.255;CTRY:;LANG:en;SCL:-1;SRV:;IPV:NLI;SFV:NSPM;H:server.example.com;PTR:;CAT:NONE;SFS:;DIR:INB;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: -1,
			expectedDesc:  "Skipped spam filtering (safe sender or SCL override)",
			expectNil:     false,
		},
		{
			name:          "SCL 0 (not spam)",
			header:        "CIP:10.0.0.1;CTRY:US;SCL:0;SRV:;IPV:CAL;SFV:NSPM;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 0,
			expectedDesc:  "Not spam",
			expectNil:     false,
		},
		{
			name:          "SCL 1 (not spam)",
			header:        "SCL:1;SRV:;IPV:CAL;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 1,
			expectedDesc:  "Not spam",
			expectNil:     false,
		},
		{
			name:          "SCL 2 (low spam probability)",
			header:        "SCL:2;PCL:0;RULEID:;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 2,
			expectedDesc:  "Low spam probability",
			expectNil:     false,
		},
		{
			name:          "SCL 3 (low spam probability)",
			header:        "CIP:192.168.1.1;SCL:3;DIR:INB;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 3,
			expectedDesc:  "Low spam probability",
			expectNil:     false,
		},
		{
			name:          "SCL 4 (low spam probability)",
			header:        "SCL:4;SFV:SPM;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 4,
			expectedDesc:  "Low spam probability",
			expectNil:     false,
		},
		{
			name:          "SCL 5 (spam)",
			header:        "CIP:203.0.113.1;CTRY:XX;SCL:5;SFV:SPM;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 5,
			expectedDesc:  "Spam",
			expectNil:     false,
		},
		{
			name:          "SCL 6 (spam)",
			header:        "SCL:6;SFV:SPM;DIR:INB;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 6,
			expectedDesc:  "Spam",
			expectNil:     false,
		},
		{
			name:          "SCL 7 (high confidence spam)",
			header:        "SCL:7;SFV:SPM;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 7,
			expectedDesc:  "High confidence spam",
			expectNil:     false,
		},
		{
			name:          "SCL 8 (high confidence spam)",
			header:        "CIP:198.51.100.1;SCL:8;SFV:SPM;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 8,
			expectedDesc:  "High confidence spam",
			expectNil:     false,
		},
		{
			name:          "SCL 9 (high confidence spam)",
			header:        "SCL:9;SFV:SPM;DIR:INB;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 9,
			expectedDesc:  "High confidence spam",
			expectNil:     false,
		},
		{
			name:         "Empty header",
			header:       "",
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    true,
		},
		{
			name:         "No SCL value",
			header:       "CIP:10.0.0.1;CTRY:US;SRV:;IPV:CAL;",
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    true,
		},
		{
			name:         "Invalid SCL (non-numeric)",
			header:       "SCL:invalid;SRV:;",
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    true,
		},
		{
			name:          "SCL at beginning of header",
			header:        "SCL:5;CIP:10.0.0.1;CTRY:US;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 5,
			expectedDesc:  "Spam",
			expectNil:     false,
		},
		{
			name:          "SCL at end of header",
			header:        "CIP:10.0.0.1;CTRY:US;SRV:;IPV:CAL;SCL:3",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 3,
			expectedDesc:  "Low spam probability",
			expectNil:     false,
		},
		{
			name:          "SCL in middle of header",
			header:        "CIP:10.0.0.1;CTRY:US;SCL:7;SRV:;IPV:CAL;DIR:INB;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 7,
			expectedDesc:  "High confidence spam",
			expectNil:     false,
		},
		{
			name:          "Multiple SCL values (first should be used)",
			header:        "SCL:2;CIP:10.0.0.1;SCL:8;CTRY:US;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 2,
			expectedDesc:  "Low spam probability",
			expectNil:     false,
		},
		{
			name:         "SCL with spaces around colon",
			header:       "CIP:10.0.0.1;SCL: 4 ;CTRY:US;",
			headerSource: "X-Forefront-Antispam-Report",
			// The regex pattern requires no space after SCL:
			expectNil: true,
		},
		{
			name:         "Out of range SCL (10)",
			header:       "SCL:10;SRV:;",
			headerSource: "X-Forefront-Antispam-Report",
			// The function logs a warning and rejects out-of-range values
			expectNil: true,
		},
		{
			name:         "Out of range SCL (-2)",
			header:       "SCL:-2;SRV:;",
			headerSource: "X-Forefront-Antispam-Report",
			// The function logs a warning and rejects out-of-range values
			expectNil: true,
		},
		{
			name:         "SCL with no value",
			header:       "SCL:;SRV:;",
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    true,
		},
		{
			name:          "SCL with decimal value",
			header:        "SCL:5.5;SRV:;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 5,
			expectedDesc:  "Spam",
			expectNil:     false,
			// Regex pattern \d+ matches digits, so it captures "5" from "5.5"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseSCLHeader(tt.header, tt.headerSource)

			if tt.expectNil {
				if result != nil {
					t.Errorf("Expected nil result, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatalf("Expected non-nil result, got nil")
			}

			if result.Score != tt.expectedScore {
				t.Errorf("Expected score %d, got %d", tt.expectedScore, result.Score)
			}

			if result.Description != tt.expectedDesc {
				t.Errorf("Expected description %q, got %q", tt.expectedDesc, result.Description)
			}

			if result.HeaderSource != tt.headerSource {
				t.Errorf("Expected header source %q, got %q", tt.headerSource, result.HeaderSource)
			}

			// Verify raw header is sanitized (no newlines)
			if strings.Contains(result.RawHeader, "\n") || strings.Contains(result.RawHeader, "\r") {
				t.Errorf("Raw header contains newlines: %q", result.RawHeader)
			}
		})
	}
}

// TestGetSCLDescription tests the getSCLDescription function
func TestGetSCLDescription(t *testing.T) {
	tests := []struct {
		score       int
		description string
	}{
		{-1, "Skipped spam filtering (safe sender or SCL override)"},
		{0, "Not spam"},
		{1, "Not spam"},
		{2, "Low spam probability"},
		{3, "Low spam probability"},
		{4, "Low spam probability"},
		{5, "Spam"},
		{6, "Spam"},
		{7, "High confidence spam"},
		{8, "High confidence spam"},
		{9, "High confidence spam"},
		{10, "Unknown spam confidence level"},
		{-2, "Unknown spam confidence level"},
		{100, "Unknown spam confidence level"},
		{-100, "Unknown spam confidence level"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			result := getSCLDescription(tt.score)
			if result != tt.description {
				t.Errorf("getSCLDescription(%d) = %q; want %q", tt.score, result, tt.description)
			}
		})
	}
}

// TestExtractSCLResults tests the extractSCLResults function
func TestExtractSCLResults(t *testing.T) {
	tests := []struct {
		name          string
		headers       map[string][]string
		expectedScore int
		expectedDesc  string
		expectNil     bool
	}{
		{
			name: "X-Forefront-Antispam-Report with SCL:5",
			headers: map[string][]string{
				"X-Forefront-Antispam-Report": {"CIP:203.0.113.1;CTRY:XX;SCL:5;SFV:SPM;"},
			},
			expectedScore: 5,
			expectedDesc:  "Spam",
			expectNil:     false,
		},
		{
			name: "X-Forefront-Antispam-Report-Untrusted with SCL:7",
			headers: map[string][]string{
				"X-Forefront-Antispam-Report-Untrusted": {"SCL:7;SFV:SPM;"},
			},
			expectedScore: 7,
			expectedDesc:  "High confidence spam",
			expectNil:     false,
		},
		{
			name: "Both headers present (trusted takes precedence)",
			headers: map[string][]string{
				"X-Forefront-Antispam-Report":           {"SCL:2;SRV:;"},
				"X-Forefront-Antispam-Report-Untrusted": {"SCL:8;SRV:;"},
			},
			expectedScore: 2,
			expectedDesc:  "Low spam probability",
			expectNil:     false,
		},
		{
			name: "No SCL headers",
			headers: map[string][]string{
				"Authentication-Results": {"example.com; spf=pass"},
			},
			expectNil: true,
		},
		{
			name: "Empty SCL header",
			headers: map[string][]string{
				"X-Forefront-Antispam-Report": {""},
			},
			expectNil: true,
		},
		{
			name: "SCL header with no SCL value",
			headers: map[string][]string{
				"X-Forefront-Antispam-Report": {"CIP:10.0.0.1;CTRY:US;SRV:;"},
			},
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert map to mail.Header
			header := make(mail.Header)
			for key, values := range tt.headers {
				header[key] = append(header[key], values...)
			}

			result := extractSCLResults(header)

			if tt.expectNil {
				if result != nil {
					t.Errorf("Expected nil result, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatalf("Expected non-nil result, got nil")
			}

			if result.Score != tt.expectedScore {
				t.Errorf("Expected score %d, got %d", tt.expectedScore, result.Score)
			}

			if result.Description != tt.expectedDesc {
				t.Errorf("Expected description %q, got %q", tt.expectedDesc, result.Description)
			}
		})
	}
}

// TestParseSCLHeaderEdgeCases tests edge cases for SCL header parsing
func TestParseSCLHeaderEdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		header        string
		headerSource  string
		expectNil     bool
		expectedScore int
		expectedDesc  string
	}{
		{
			name: "Very long header",
			header: "CIP:10.0.0.1;CTRY:US;LANG:en;SCL:5;SRV:;IPV:CAL;SFV:SPM;" +
				strings.Repeat("A", 10000),
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    false,
		},
		{
			name:         "Header with newlines (should be sanitized)",
			header:       "CIP:10.0.0.1;\nSCL:3;\r\nCTRY:US;",
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    false,
		},
		{
			name:         "Header with special characters",
			header:       "CIP:10.0.0.1;SCL:4;CTRY:US;EXTRA:<script>alert('xss')</script>",
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    false,
		},
		{
			name:         "Header with Unicode characters",
			header:       "CIP:10.0.0.1;SCL:2;CTRY:日本;",
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    false,
		},
		{
			name:         "Case sensitivity test (lowercase scl)",
			header:       "CIP:10.0.0.1;scl:5;CTRY:US;",
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    true, // Regex looks for uppercase SCL
		},
		{
			name:         "Mixed case SCL",
			header:       "CIP:10.0.0.1;Scl:5;CTRY:US;",
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    true, // Regex looks for uppercase SCL
		},
		{
			name:         "SCL with leading zeros",
			header:       "SCL:05;SRV:;",
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    false,
		},
		{
			name:         "SCL with plus sign",
			header:       "SCL:+5;SRV:;",
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    true, // Regex only matches optional minus sign
		},
		{
			name:          "SCL-like but not SCL",
			header:        "XSCL:5;SCLX:7;MYSCL:9;",
			headerSource:  "X-Forefront-Antispam-Report",
			expectedScore: 5,
			expectedDesc:  "Spam",
			expectNil:     false,
			// Regex pattern "SCL:" will match "XSCL:5" (the "SCL:5" part)
		},
		{
			name:         "SCL with whitespace",
			header:       "SCL : 5 ; SRV:;",
			headerSource: "X-Forefront-Antispam-Report",
			expectNil:    true, // Regex doesn't allow spaces
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseSCLHeader(tt.header, tt.headerSource)

			if tt.expectNil {
				if result != nil {
					t.Errorf("Expected nil result for %q, got %+v", tt.name, result)
				}
			} else {
				if result == nil {
					t.Errorf("Expected non-nil result for %q, got nil", tt.name)
				} else {
					// Optionally verify score and description if specified
					if tt.expectedScore != 0 && result.Score != tt.expectedScore {
						t.Errorf("Expected score %d, got %d", tt.expectedScore, result.Score)
					}
					if tt.expectedDesc != "" && result.Description != tt.expectedDesc {
						t.Errorf("Expected description %q, got %q", tt.expectedDesc, result.Description)
					}
				}
			}
		})
	}
}

// TestSCLResultStruct tests that SCLResult struct is properly populated
func TestSCLResultStruct(t *testing.T) {
	header := "CIP:10.0.0.1;CTRY:US;SCL:6;SRV:;IPV:CAL;"
	headerSource := "X-Forefront-Antispam-Report"

	result := parseSCLHeader(header, headerSource)

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	// Check all fields are populated
	if result.Score != 6 {
		t.Errorf("Expected Score=6, got %d", result.Score)
	}

	if result.Description != "Spam" {
		t.Errorf("Expected Description='Spam', got %q", result.Description)
	}

	if result.HeaderSource != headerSource {
		t.Errorf("Expected HeaderSource=%q, got %q", headerSource, result.HeaderSource)
	}

	if result.RawHeader == "" {
		t.Error("Expected RawHeader to be populated, got empty string")
	}

	// Verify RawHeader is sanitized
	if strings.Contains(result.RawHeader, "\n") || strings.Contains(result.RawHeader, "\r") {
		t.Errorf("RawHeader should not contain newlines: %q", result.RawHeader)
	}
}

// TestSCLHeaderLengthValidation tests that excessively long headers are truncated
func TestSCLHeaderLengthValidation(t *testing.T) {
	// Create a header longer than MaxHeaderLength
	longHeader := "SCL:5;" + strings.Repeat("A", MaxHeaderLength+1000)

	header := make(mail.Header)
	header["X-Forefront-Antispam-Report"] = []string{longHeader}

	result := extractSCLResults(header)

	if result == nil {
		t.Fatal("Expected non-nil result even with truncated header")
	}

	// The raw header should be truncated to MaxHeaderLength
	if len(result.RawHeader) > MaxHeaderLength {
		t.Errorf("RawHeader length %d exceeds MaxHeaderLength %d",
			len(result.RawHeader), MaxHeaderLength)
	}
}

// TestMultipleSCLValuesInHeader tests that only the first SCL value is extracted
func TestMultipleSCLValuesInHeader(t *testing.T) {
	header := "SCL:1;CIP:10.0.0.1;SCL:9;CTRY:US;SCL:5;"
	headerSource := "X-Forefront-Antispam-Report"

	result := parseSCLHeader(header, headerSource)

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	// Should use the first SCL value (1)
	if result.Score != 1 {
		t.Errorf("Expected first SCL value (1), got %d", result.Score)
	}

	if result.Description != "Not spam" {
		t.Errorf("Expected 'Not spam' description, got %q", result.Description)
	}
}

// TestSCLBoundaryValues tests SCL values at boundaries
func TestSCLBoundaryValues(t *testing.T) {
	tests := []struct {
		score        int
		description  string
		categoryName string
	}{
		{-1, "Skipped spam filtering (safe sender or SCL override)", "Skipped"},
		{0, "Not spam", "Not spam lower bound"},
		{1, "Not spam", "Not spam upper bound"},
		{2, "Low spam probability", "Low spam lower bound"},
		{3, "Low spam probability", "Low spam middle"},
		{4, "Low spam probability", "Low spam upper bound"},
		{5, "Spam", "Spam lower bound"},
		{6, "Spam", "Spam upper bound"},
		{7, "High confidence spam", "High spam lower bound"},
		{8, "High confidence spam", "High spam middle"},
		{9, "High confidence spam", "High spam upper bound"},
	}

	for _, tt := range tests {
		t.Run(tt.categoryName, func(t *testing.T) {
			desc := getSCLDescription(tt.score)
			if desc != tt.description {
				t.Errorf("Score %d: expected %q, got %q", tt.score, tt.description, desc)
			}
		})
	}
}

// ============================================================================
// DMARC Aggregate Report Tests
// ============================================================================

// TestParseDMARCReportSecure tests basic DMARC XML parsing
func TestParseDMARCReportSecure(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantErr     bool
		wantRecords int
		wantOrg     string
		wantDomain  string
	}{
		{
			name: "valid simple report",
			input: `<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply@google.com</email>
    <report_id>12345</report_id>
    <date_range><begin>1700000000</begin><end>1700086400</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <p>none</p><sp>none</sp><pct>100</pct>
    <adkim>r</adkim><aspf>r</aspf>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.1</source_ip>
      <count>5</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results>
      <spf><domain>example.com</domain><result>pass</result></spf>
    </auth_results>
  </record>
</feedback>`,
			wantErr:     false,
			wantRecords: 1,
			wantOrg:     "google.com",
			wantDomain:  "example.com",
		},
		{
			name: "multiple records",
			input: `<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>yahoo.com</org_name>
    <email>dmarc@yahoo.com</email>
    <report_id>67890</report_id>
    <date_range><begin>1700000000</begin><end>1700086400</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>test.com</domain>
    <p>quarantine</p><sp>quarantine</sp><pct>100</pct>
    <adkim>s</adkim><aspf>s</aspf>
  </policy_published>
  <record>
    <row><source_ip>192.0.2.1</source_ip><count>10</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>test.com</header_from></identifiers>
    <auth_results><spf><domain>test.com</domain><result>pass</result></spf></auth_results>
  </record>
  <record>
    <row><source_ip>192.0.2.2</source_ip><count>3</count>
      <policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
    </row>
    <identifiers><header_from>test.com</header_from></identifiers>
    <auth_results><spf><domain>test.com</domain><result>fail</result></spf></auth_results>
  </record>
</feedback>`,
			wantErr:     false,
			wantRecords: 2,
			wantOrg:     "yahoo.com",
			wantDomain:  "test.com",
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid XML",
			input:   "<not valid xml",
			wantErr: true,
		},
		{
			name:    "wrong root element",
			input:   `<?xml version="1.0"?><html><body>Not DMARC</body></html>`,
			wantErr: true, // Will fail validation due to missing required fields
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := parseDMARCReportSecure(strings.NewReader(tt.input))

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(report.Records) != tt.wantRecords {
				t.Errorf("got %d records, want %d", len(report.Records), tt.wantRecords)
			}

			if report.Metadata.OrgName != tt.wantOrg {
				t.Errorf("got org %q, want %q", report.Metadata.OrgName, tt.wantOrg)
			}

			if report.PolicyPublished.Domain != tt.wantDomain {
				t.Errorf("got domain %q, want %q", report.PolicyPublished.Domain, tt.wantDomain)
			}
		})
	}
}

// TestValidateDMARCRecord tests record validation
func TestValidateDMARCRecord(t *testing.T) {
	tests := []struct {
		name    string
		record  DMARCAggregateRecord
		wantErr bool
	}{
		{
			name: "valid IPv4",
			record: DMARCAggregateRecord{
				Row: DMARCRow{
					SourceIP: "192.0.2.1",
					Count:    10,
					PolicyEvaluated: DMARCPolicyEvaluated{
						Disposition: "none",
						DKIM:        "pass",
						SPF:         "pass",
					},
				},
				Identifiers: DMARCIdentifiers{HeaderFrom: "example.com"},
			},
			wantErr: false,
		},
		{
			name: "valid IPv6",
			record: DMARCAggregateRecord{
				Row: DMARCRow{
					SourceIP: "2001:db8::1",
					Count:    5,
					PolicyEvaluated: DMARCPolicyEvaluated{
						Disposition: "quarantine",
						DKIM:        "fail",
						SPF:         "pass",
					},
				},
				Identifiers: DMARCIdentifiers{HeaderFrom: "example.com"},
			},
			wantErr: false,
		},
		{
			name: "invalid IP",
			record: DMARCAggregateRecord{
				Row: DMARCRow{
					SourceIP: "invalid-ip",
					Count:    1,
					PolicyEvaluated: DMARCPolicyEvaluated{
						Disposition: "none",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "negative count",
			record: DMARCAggregateRecord{
				Row: DMARCRow{
					SourceIP: "192.0.2.1",
					Count:    -1,
					PolicyEvaluated: DMARCPolicyEvaluated{
						Disposition: "none",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid disposition",
			record: DMARCAggregateRecord{
				Row: DMARCRow{
					SourceIP: "192.0.2.1",
					Count:    1,
					PolicyEvaluated: DMARCPolicyEvaluated{
						Disposition: "invalid_disposition",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "empty disposition (valid - defaults to none)",
			record: DMARCAggregateRecord{
				Row: DMARCRow{
					SourceIP: "192.0.2.1",
					Count:    1,
					PolicyEvaluated: DMARCPolicyEvaluated{
						Disposition: "",
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDMARCRecord(&tt.record, 0)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateDMARCRecord() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestAnalyzeDMARCReport tests the analysis function
func TestAnalyzeDMARCReport(t *testing.T) {
	report := &DMARCAggregateReport{
		Metadata: DMARCReportMetadata{
			OrgName:  "test.com",
			ReportID: "123",
		},
		PolicyPublished: DMARCPolicyPublished{
			Domain: "example.com",
			Policy: "none",
		},
		Records: []DMARCAggregateRecord{
			{
				Row: DMARCRow{
					SourceIP: "192.0.2.1",
					Count:    100,
					PolicyEvaluated: DMARCPolicyEvaluated{
						Disposition: "none",
						SPF:         "pass",
						DKIM:        "pass",
					},
				},
			},
			{
				Row: DMARCRow{
					SourceIP: "192.0.2.2",
					Count:    50,
					PolicyEvaluated: DMARCPolicyEvaluated{
						Disposition: "none",
						SPF:         "fail",
						DKIM:        "pass",
					},
				},
			},
			{
				Row: DMARCRow{
					SourceIP: "192.0.2.3",
					Count:    25,
					PolicyEvaluated: DMARCPolicyEvaluated{
						Disposition: "quarantine",
						SPF:         "fail",
						DKIM:        "fail",
					},
				},
			},
		},
	}

	analysis := analyzeDMARCReport(report)

	if analysis.TotalEmails != 175 {
		t.Errorf("got TotalEmails %d, want 175", analysis.TotalEmails)
	}

	// Only the first record (100 emails) has both pass
	expectedPassRate := 100.0 / 175.0 * 100
	if diff := analysis.PassRate - expectedPassRate; diff > 0.1 || diff < -0.1 {
		t.Errorf("got PassRate %.2f, want %.2f", analysis.PassRate, expectedPassRate)
	}

	// 100 SPF pass out of 175
	expectedSPFRate := 100.0 / 175.0 * 100
	if diff := analysis.SPFPassRate - expectedSPFRate; diff > 0.1 || diff < -0.1 {
		t.Errorf("got SPFPassRate %.2f, want %.2f", analysis.SPFPassRate, expectedSPFRate)
	}

	// 150 DKIM pass out of 175 (first two records)
	expectedDKIMRate := 150.0 / 175.0 * 100
	if diff := analysis.DKIMPassRate - expectedDKIMRate; diff > 0.1 || diff < -0.1 {
		t.Errorf("got DKIMPassRate %.2f, want %.2f", analysis.DKIMPassRate, expectedDKIMRate)
	}

	// Should have 2 failing sources (records 2 and 3)
	if len(analysis.FailingSources) != 2 {
		t.Errorf("got %d failing sources, want 2", len(analysis.FailingSources))
	}
}

// TestCalculateDMARCThreatScore tests threat scoring
func TestCalculateDMARCThreatScore(t *testing.T) {
	tests := []struct {
		name      string
		spf       string
		dkim      string
		disp      string
		count     int
		avgVolume float64
		minScore  float64
		maxScore  float64
	}{
		{
			name:      "all pass",
			spf:       "pass",
			dkim:      "pass",
			disp:      "none",
			count:     10,
			avgVolume: 100,
			minScore:  0,
			maxScore:  10,
		},
		{
			name:      "SPF fail only",
			spf:       "fail",
			dkim:      "pass",
			disp:      "none",
			count:     10,
			avgVolume: 100,
			minScore:  20,
			maxScore:  30,
		},
		{
			name:      "both fail",
			spf:       "fail",
			dkim:      "fail",
			disp:      "none",
			count:     10,
			avgVolume: 100,
			minScore:  40,
			maxScore:  50,
		},
		{
			name:      "both fail + reject",
			spf:       "fail",
			dkim:      "fail",
			disp:      "reject",
			count:     10,
			avgVolume: 100,
			minScore:  60,
			maxScore:  70,
		},
		{
			name:      "high volume anomaly",
			spf:       "fail",
			dkim:      "fail",
			disp:      "reject",
			count:     1000,
			avgVolume: 100,
			minScore:  90,
			maxScore:  100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := &DMARCAggregateRecord{
				Row: DMARCRow{
					SourceIP: "192.0.2.1",
					Count:    tt.count,
					PolicyEvaluated: DMARCPolicyEvaluated{
						Disposition: tt.disp,
						DKIM:        tt.dkim,
						SPF:         tt.spf,
					},
				},
			}

			score := calculateDMARCThreatScore(record, tt.avgVolume)

			if score < tt.minScore || score > tt.maxScore {
				t.Errorf("got score %.0f, want between %.0f and %.0f", score, tt.minScore, tt.maxScore)
			}
		})
	}
}

// TestThreatLevelFromScore tests threat level classification
func TestThreatLevelFromScore(t *testing.T) {
	tests := []struct {
		score float64
		level string
	}{
		{0, "low"},
		{29, "low"},
		{30, "medium"},
		{49, "medium"},
		{50, "high"},
		{69, "high"},
		{70, "critical"},
		{100, "critical"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%.0f-%s", tt.score, tt.level), func(t *testing.T) {
			result := threatLevelFromScore(tt.score)
			if result != tt.level {
				t.Errorf("threatLevelFromScore(%.0f) = %q, want %q", tt.score, result, tt.level)
			}
		})
	}
}

// TestDetermineDMARCFailReason tests fail reason determination
func TestDetermineDMARCFailReason(t *testing.T) {
	tests := []struct {
		name   string
		spf    string
		dkim   string
		reason string
	}{
		{"both fail", "fail", "fail", "Both SPF and DKIM failed"},
		{"SPF fail only", "fail", "pass", "SPF failed"},
		{"DKIM fail only", "pass", "fail", "DKIM failed"},
		{"both pass", "pass", "pass", "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := DMARCAggregateRecord{
				Row: DMARCRow{
					PolicyEvaluated: DMARCPolicyEvaluated{
						SPF:  tt.spf,
						DKIM: tt.dkim,
					},
				},
			}
			result := determineDMARCFailReason(record)
			if result != tt.reason {
				t.Errorf("got %q, want %q", result, tt.reason)
			}
		})
	}
}

// TestGenerateDMARCRecommendations tests recommendation generation
func TestGenerateDMARCRecommendations(t *testing.T) {
	// Test policy=none generates recommendation
	report := &DMARCAggregateReport{
		PolicyPublished: DMARCPolicyPublished{
			Domain:     "example.com",
			Policy:     "none",
			Percentage: 100,
		},
	}
	analysis := &DMARCReportAnalysis{
		PassRate:     95,
		SPFPassRate:  100,
		DKIMPassRate: 100,
	}

	recs := generateDMARCRecommendations(report, analysis)

	foundPolicyRec := false
	for _, rec := range recs {
		if rec.Category == "policy" && strings.Contains(rec.Title, "Upgrade") {
			foundPolicyRec = true
		}
	}
	if !foundPolicyRec {
		t.Error("expected policy upgrade recommendation for policy=none")
	}

	// Test low SPF pass rate generates recommendation
	analysis2 := &DMARCReportAnalysis{
		PassRate:     50,
		SPFPassRate:  50,
		DKIMPassRate: 100,
	}
	recs2 := generateDMARCRecommendations(report, analysis2)

	foundSPFRec := false
	for _, rec := range recs2 {
		if rec.Category == "spf" {
			foundSPFRec = true
		}
	}
	if !foundSPFRec {
		t.Error("expected SPF recommendation for low pass rate")
	}
}

// TestFormatUnixTime tests time formatting
func TestFormatUnixTime(t *testing.T) {
	// Test a known timestamp
	// 1700000000 = 2023-11-14 22:13:20 UTC
	result := formatUnixTime(1700000000)
	if !strings.Contains(result, "2023-11-14") {
		t.Errorf("formatUnixTime(1700000000) = %q, expected to contain 2023-11-14", result)
	}
	if !strings.Contains(result, "UTC") {
		t.Errorf("formatUnixTime(1700000000) = %q, expected to contain UTC", result)
	}
}

// TestSanitizeDMARCDomain tests domain sanitization
func TestSanitizeDMARCDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"  example.com  ", "example.com"},
		{"example\x00.com", "example.com"},                   // null byte removed
		{"example\n.com", "example.com"},                     // newline removed
		{strings.Repeat("a", 300), strings.Repeat("a", 255)}, // truncated to 255
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := sanitizeDMARCDomain(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeDMARCDomain(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestSanitizeDMARCError tests error message sanitization
func TestSanitizeDMARCError(t *testing.T) {
	tests := []struct {
		errMsg   string
		contains string
	}{
		{"path traversal detected", "Invalid file path"},
		{"exceeds maximum size", "too large"},
		{"failed to parse XML", "not valid DMARC XML"},
		{"compression ratio exceeded", "malformed"},
		{"no DMARC XML file found", "No valid DMARC report"},
		{"random unknown error", "valid DMARC aggregate report"},
	}

	for _, tt := range tests {
		t.Run(tt.errMsg, func(t *testing.T) {
			// Create a mock error using fmt.Errorf
			mockErr := fmt.Errorf("%s", tt.errMsg)
			result := sanitizeDMARCError(mockErr)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("sanitizeDMARCError(%q) = %q, expected to contain %q", tt.errMsg, result, tt.contains)
			}
		})
	}
}

// TestPassRateSymbol tests pass rate symbol generation
func TestPassRateSymbol(t *testing.T) {
	tests := []struct {
		rate   float64
		symbol string
	}{
		{100, "✓"},
		{95, "✓"},
		{94, "⚠"},
		{80, "⚠"},
		{79, "✗"},
		{0, "✗"},
	}

	for _, tt := range tests {
		result := passRateSymbol(tt.rate)
		if result != tt.symbol {
			t.Errorf("passRateSymbol(%.0f) = %q, want %q", tt.rate, result, tt.symbol)
		}
	}
}

// TestThreatSymbol tests threat level symbol generation
func TestThreatSymbol(t *testing.T) {
	tests := []struct {
		level  string
		symbol string
	}{
		{"low", "✓"},
		{"medium", "⚠"},
		{"high", "✗"},
		{"critical", "✗✗"},
		{"unknown", ""},
	}

	for _, tt := range tests {
		result := threatSymbol(tt.level)
		if result != tt.symbol {
			t.Errorf("threatSymbol(%q) = %q, want %q", tt.level, result, tt.symbol)
		}
	}
}

// TestEscapeMarkdown tests markdown escaping
func TestEscapeMarkdown(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"normal text", "normal text"},
		{"text|with|pipes", "text\\|with\\|pipes"},
		{"|leading", "\\|leading"},
		{"trailing|", "trailing\\|"},
	}

	for _, tt := range tests {
		result := escapeMarkdown(tt.input)
		if result != tt.expected {
			t.Errorf("escapeMarkdown(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

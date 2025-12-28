package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/emersion/go-message/charset"
	"github.com/oschwald/geoip2-golang"
	"github.com/rotisserie/eris"
	"github.com/yeka/zip"
)

// Security configuration constants
const (
	MaxFileSizeBytes     = 50 * 1024 * 1024  // 50MB limit
	MaxHeaderLength      = 10000             // Maximum header field length
	MaxZipFiles          = 100               // Maximum files in ZIP archive
	MaxUncompressedSize  = 100 * 1024 * 1024 // 100MB uncompressed limit
	MaxCompressionRatio  = 100               // 100:1 compression ratio limit
	MaxHeaderSearchBytes = 10000             // Limit for binary header search
	MaxRegexMatches      = 50                // Limit regex matches to prevent ReDoS

	// DMARC aggregate report limits
	MaxDMARCReportSize  = 50 * 1024 * 1024 // 50MB max DMARC report size
	MaxRecordsPerReport = 100000           // Maximum records in a DMARC report
	MaxStringLength     = 10000            // Maximum string field length in DMARC report
	MaxRecordCount      = 1000000000       // Maximum email count per record (1 billion)
)

// EmailSecurityReport contains the analysis results of email security headers
type EmailSecurityReport struct {
	From         string              `json:"from"`
	To           string              `json:"to"`
	Subject      string              `json:"subject"`
	Date         string              `json:"date"`
	MessageID    string              `json:"message_id"`
	SPFResults   []SPFResult         `json:"spf_results"`
	DKIMResults  []DKIMResult        `json:"dkim_results"`
	DMARCResults []DMARCResult       `json:"dmarc_results"`
	AuthResults  []AuthResult        `json:"auth_results"`
	ARCResults   []ARCResult         `json:"arc_results"`
	SCL          *SCLResult          `json:"scl,omitempty"`
	ReceivedSPF  string              `json:"received_spf"`
	RawHeaders   map[string][]string `json:"raw_headers,omitempty"`
}

// SPFResult represents SPF authentication result
type SPFResult struct {
	Result      string `json:"result"` // pass, fail, softfail, neutral, none, temperror, permerror
	Domain      string `json:"domain"`
	Explanation string `json:"explanation"`
	ClientIP    string `json:"client_ip,omitempty"`
}

// DKIMResult represents DKIM signature validation result
type DKIMResult struct {
	Result    string `json:"result"` // pass, fail, neutral, temperror, permerror, none
	Domain    string `json:"domain"`
	Selector  string `json:"selector"`
	Signature string `json:"signature,omitempty"`
	HeaderD   string `json:"header_d,omitempty"` // d= parameter
	HeaderS   string `json:"header_s,omitempty"` // s= parameter
	HeaderA   string `json:"header_a,omitempty"` // a= algorithm
}

// DMARCResult represents DMARC policy evaluation result
type DMARCResult struct {
	Result          string `json:"result"`         // pass, fail, none
	Policy          string `json:"policy"`         // none, quarantine, reject
	Disposition     string `json:"disposition"`    // none, quarantine, reject
	SPFAlignment    string `json:"spf_alignment"`  // pass, fail
	DKIMAlignment   string `json:"dkim_alignment"` // pass, fail
	Domain          string `json:"domain"`
	SubdomainPolicy string `json:"subdomain_policy,omitempty"`
}

// AuthResult represents parsed Authentication-Results header
type AuthResult struct {
	AuthServID string       `json:"authserv_id"`
	Version    int          `json:"version,omitempty"`
	Methods    []AuthMethod `json:"methods"`
}

// AuthMethod represents individual authentication method result
type AuthMethod struct {
	Method     string            `json:"method"` // spf, dkim, dmarc, arc
	Result     string            `json:"result"`
	Reason     string            `json:"reason,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

// ARCResult represents ARC (Authenticated Received Chain) result
type ARCResult struct {
	Instance int    `json:"instance"` // i= parameter
	Result   string `json:"result"`   // pass, fail, none
	Chain    string `json:"chain"`    // none, fail, pass
}

// SCLResult represents Microsoft Spam Confidence Level result
type SCLResult struct {
	Score        int    `json:"score"`         // -1 to 9 (higher = more likely spam)
	Description  string `json:"description"`   // Human-readable description
	HeaderSource string `json:"header_source"` // Source header name
	RawHeader    string `json:"raw_header"`    // Full header value
}

// ============================================================================
// DMARC Aggregate Report Types (RFC 7489)
// ============================================================================

// DMARCAggregateReport represents a complete DMARC aggregate report
type DMARCAggregateReport struct {
	XMLName         xml.Name               `xml:"feedback" json:"-"`
	Version         string                 `xml:"version" json:"version,omitempty"`
	Metadata        DMARCReportMetadata    `xml:"report_metadata" json:"metadata"`
	PolicyPublished DMARCPolicyPublished   `xml:"policy_published" json:"policy_published"`
	Records         []DMARCAggregateRecord `xml:"record" json:"records"`
	Analysis        *DMARCReportAnalysis   `json:"analysis,omitempty"`
}

// DMARCReportMetadata contains report identification information
type DMARCReportMetadata struct {
	OrgName          string         `xml:"org_name" json:"org_name"`
	Email            string         `xml:"email" json:"email"`
	ExtraContactInfo string         `xml:"extra_contact_info,omitempty" json:"extra_contact_info,omitempty"`
	ReportID         string         `xml:"report_id" json:"report_id"`
	DateRange        DMARCDateRange `xml:"date_range" json:"date_range"`
}

// DMARCDateRange represents the reporting period
type DMARCDateRange struct {
	Begin int64 `xml:"begin" json:"begin"`
	End   int64 `xml:"end" json:"end"`
}

// DMARCPolicyPublished represents the domain's DMARC policy at report time
type DMARCPolicyPublished struct {
	Domain          string `xml:"domain" json:"domain"`
	ADKIM           string `xml:"adkim" json:"adkim"`               // r=relaxed, s=strict
	ASPF            string `xml:"aspf" json:"aspf"`                 // r=relaxed, s=strict
	Policy          string `xml:"p" json:"p"`                       // none, quarantine, reject
	SubdomainPolicy string `xml:"sp" json:"sp"`                     // none, quarantine, reject
	Percentage      int    `xml:"pct" json:"pct"`                   // 0-100
	FailureOptions  string `xml:"fo,omitempty" json:"fo,omitempty"` // 0, 1, d, s
	NoPolicy        string `xml:"np,omitempty" json:"np,omitempty"` // non-existent subdomain policy
}

// DMARCAggregateRecord represents a single record in the report
type DMARCAggregateRecord struct {
	Row         DMARCRow         `xml:"row" json:"row"`
	Identifiers DMARCIdentifiers `xml:"identifiers" json:"identifiers"`
	AuthResults DMARCAuthResults `xml:"auth_results" json:"auth_results"`
	Enrichment  *IPEnrichment    `json:"enrichment,omitempty"`
}

// DMARCRow contains the core authentication data
type DMARCRow struct {
	SourceIP        string               `xml:"source_ip" json:"source_ip"`
	Count           int                  `xml:"count" json:"count"`
	PolicyEvaluated DMARCPolicyEvaluated `xml:"policy_evaluated" json:"policy_evaluated"`
}

// DMARCPolicyEvaluated contains the disposition and authentication results
type DMARCPolicyEvaluated struct {
	Disposition string              `xml:"disposition" json:"disposition"` // none, quarantine, reject
	DKIM        string              `xml:"dkim" json:"dkim"`               // pass, fail
	SPF         string              `xml:"spf" json:"spf"`                 // pass, fail
	Reason      []DMARCPolicyReason `xml:"reason,omitempty" json:"reason,omitempty"`
}

// DMARCPolicyReason explains override decisions
type DMARCPolicyReason struct {
	Type    string `xml:"type" json:"type"` // forwarded, local_policy, etc.
	Comment string `xml:"comment" json:"comment"`
}

// DMARCIdentifiers contains domain identifiers
type DMARCIdentifiers struct {
	EnvelopeTo   string `xml:"envelope_to,omitempty" json:"envelope_to,omitempty"`
	EnvelopeFrom string `xml:"envelope_from,omitempty" json:"envelope_from,omitempty"`
	HeaderFrom   string `xml:"header_from" json:"header_from"`
}

// DMARCAuthResults contains SPF and DKIM authentication details
type DMARCAuthResults struct {
	DKIM []DMARCDKIMAuthResult `xml:"dkim,omitempty" json:"dkim,omitempty"`
	SPF  []DMARCSPFAuthResult  `xml:"spf,omitempty" json:"spf,omitempty"`
}

// DMARCDKIMAuthResult represents a DKIM authentication check in DMARC report
type DMARCDKIMAuthResult struct {
	Domain      string `xml:"domain" json:"domain"`
	Selector    string `xml:"selector,omitempty" json:"selector,omitempty"`
	Result      string `xml:"result" json:"result"` // pass, fail, neutral, etc.
	HumanResult string `xml:"human_result,omitempty" json:"human_result,omitempty"`
}

// DMARCSPFAuthResult represents an SPF authentication check in DMARC report
type DMARCSPFAuthResult struct {
	Domain string `xml:"domain" json:"domain"`
	Scope  string `xml:"scope,omitempty" json:"scope,omitempty"` // mfrom, helo
	Result string `xml:"result" json:"result"`                   // pass, fail, softfail, etc.
}

// IPEnrichment contains geolocation and threat data for an IP
type IPEnrichment struct {
	Country      string  `json:"country,omitempty"`
	CountryCode  string  `json:"country_code,omitempty"`
	City         string  `json:"city,omitempty"`
	ASN          uint    `json:"asn,omitempty"`
	Organization string  `json:"organization,omitempty"`
	ThreatScore  float64 `json:"threat_score"`
	ThreatLevel  string  `json:"threat_level"` // low, medium, high, critical
}

// DMARCReportAnalysis contains aggregated forensic analysis
type DMARCReportAnalysis struct {
	TotalEmails        int                   `json:"total_emails"`
	PassRate           float64               `json:"pass_rate"`
	SPFPassRate        float64               `json:"spf_pass_rate"`
	DKIMPassRate       float64               `json:"dkim_pass_rate"`
	DispositionStats   map[string]int        `json:"disposition_stats"`
	TopSourceCountries []DMARCCountryStat    `json:"top_source_countries,omitempty"`
	TopASNs            []DMARCASNStat        `json:"top_asns,omitempty"`
	FailingSources     []DMARCFailingSource  `json:"failing_sources,omitempty"`
	Recommendations    []DMARCRecommendation `json:"recommendations,omitempty"`
	OverallThreatLevel string                `json:"overall_threat_level"`
}

// DMARCCountryStat represents email volume by country
type DMARCCountryStat struct {
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	EmailCount  int    `json:"email_count"`
	FailCount   int    `json:"fail_count"`
}

// DMARCASNStat represents email volume by ASN
type DMARCASNStat struct {
	ASN          uint   `json:"asn"`
	Organization string `json:"organization"`
	EmailCount   int    `json:"email_count"`
	FailCount    int    `json:"fail_count"`
}

// DMARCFailingSource represents a source with authentication failures
type DMARCFailingSource struct {
	IP           string `json:"ip"`
	Country      string `json:"country,omitempty"`
	Organization string `json:"organization,omitempty"`
	FailCount    int    `json:"fail_count"`
	FailReason   string `json:"fail_reason"`
}

// DMARCRecommendation represents an actionable suggestion
type DMARCRecommendation struct {
	Priority    string `json:"priority"` // high, medium, low
	Category    string `json:"category"` // policy, spf, dkim, monitoring
	Title       string `json:"title"`
	Description string `json:"description"`
	Action      string `json:"action"`
}

func main() {
	// Check if first arg is a subcommand
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "dmarc":
			runDMARCCommand(os.Args[2:])
			return
		case "help", "-h", "--help":
			printHelp()
			return
		case "version", "-V", "--version":
			fmt.Println("email v1.1.0")
			return
		}
	}

	// Default: existing email analysis behavior
	runEmailAnalysis()
}

// printHelp displays help information for all commands
func printHelp() {
	fmt.Println("email - Email Security Analysis Tool")
	fmt.Println()
	fmt.Println("USAGE:")
	fmt.Println("  email [-v] [-json] <email-file>          Analyze email headers")
	fmt.Println("  email dmarc [options] <report-file>      Analyze DMARC aggregate report")
	fmt.Println("  email help                               Show this help message")
	fmt.Println("  email version                            Show version information")
	fmt.Println()
	fmt.Println("EMAIL ANALYSIS OPTIONS:")
	fmt.Println("  -v           Verbose output (include all raw headers)")
	fmt.Println("  -json        Output results as JSON")
	fmt.Println()
	fmt.Println("DMARC REPORT OPTIONS:")
	fmt.Println("  -v           Verbose output (show all records)")
	fmt.Println("  -json        Output as JSON")
	fmt.Println("  -md          Output as Markdown")
	fmt.Println("  -no-enrich   Skip IP geolocation enrichment")
	fmt.Println("  -geoip-db    Path to MaxMind GeoIP2 database")
	fmt.Println()
	fmt.Println("EXAMPLES:")
	fmt.Println("  email sample.msg                         Analyze an email file")
	fmt.Println("  email -json sample.eml                   Output email analysis as JSON")
	fmt.Println("  email dmarc report.xml                   Analyze DMARC report")
	fmt.Println("  email dmarc -json report.xml.gz          Output DMARC analysis as JSON")
	fmt.Println("  email dmarc -md report.zip               Output DMARC analysis as Markdown")
}

// runEmailAnalysis runs the original email header analysis
func runEmailAnalysis() {
	// Parse command-line flags
	verbose := flag.Bool("v", false, "Verbose output (include raw headers)")
	jsonOutput := flag.Bool("json", false, "Output results as JSON")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [-v] [-json] <email-file>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nSupported formats: .msg, .eml\n")
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		fmt.Fprintf(os.Stderr, "  -v       Verbose output (include all raw headers)\n")
		fmt.Fprintf(os.Stderr, "  -json    Output results as JSON\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s sample-email.msg\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s sample-email.eml\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -json sample-email.eml\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nSubcommands:\n")
		fmt.Fprintf(os.Stderr, "  %s dmarc <report-file>   Analyze DMARC aggregate reports\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s help                  Show detailed help\n", os.Args[0])
		os.Exit(1)
	}

	msgFile := flag.Arg(0)

	// Parse the email file (.msg or .eml)
	report, err := parseEmailFile(msgFile, *verbose)
	if err != nil {
		// Log detailed error internally for debugging
		log.Printf("Internal error: %+v", err)
		// Show sanitized error to user
		fmt.Fprintf(os.Stderr, "Error: Failed to parse email file. Please ensure the file is a valid .msg or .eml format.\n")
		os.Exit(1)
	}

	// Output results
	if *jsonOutput {
		outputJSON(report)
	} else {
		outputText(report, *verbose)
	}
}

// runDMARCCommand handles the dmarc subcommand for parsing DMARC aggregate reports
func runDMARCCommand(args []string) {
	// Create new FlagSet for dmarc subcommand
	dmarcFlags := flag.NewFlagSet("dmarc", flag.ExitOnError)
	verbose := dmarcFlags.Bool("v", false, "Verbose output (show all records)")
	jsonOutput := dmarcFlags.Bool("json", false, "Output as JSON")
	markdownOutput := dmarcFlags.Bool("md", false, "Output as Markdown")
	noEnrich := dmarcFlags.Bool("no-enrich", false, "Skip IP geolocation enrichment")
	geoDBPath := dmarcFlags.String("geoip-db", "", "Path to GeoIP2 database")

	if err := dmarcFlags.Parse(args); err != nil {
		os.Exit(1)
	}

	if dmarcFlags.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s dmarc [-v] [-json|-md] [-no-enrich] [-geoip-db PATH] <report-file>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nSupported formats: .xml, .xml.gz, .zip\n")
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		fmt.Fprintf(os.Stderr, "  -v           Verbose output (show all records)\n")
		fmt.Fprintf(os.Stderr, "  -json        Output as JSON\n")
		fmt.Fprintf(os.Stderr, "  -md          Output as Markdown\n")
		fmt.Fprintf(os.Stderr, "  -no-enrich   Skip IP geolocation enrichment\n")
		fmt.Fprintf(os.Stderr, "  -geoip-db    Path to MaxMind GeoIP2 database\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s dmarc google-report.xml\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s dmarc -json report.xml.gz > analysis.json\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s dmarc -md report.zip > report.md\n", os.Args[0])
		os.Exit(1)
	}

	reportFile := dmarcFlags.Arg(0)

	// Parse the DMARC report
	report, err := parseDMARCReportFile(reportFile)
	if err != nil {
		log.Printf("Internal error: %+v", err)
		fmt.Fprintf(os.Stderr, "Error: Failed to parse DMARC report. %s\n", sanitizeDMARCError(err))
		os.Exit(1)
	}

	// Enrich with IP data unless disabled
	if !*noEnrich {
		enrichDMARCReport(report, *geoDBPath)
	}

	// Analyze the report
	report.Analysis = analyzeDMARCReport(report)

	// Output based on format
	switch {
	case *jsonOutput:
		outputDMARCJSON(report)
	case *markdownOutput:
		outputDMARCMarkdown(report, *verbose)
	default:
		outputDMARCText(report, *verbose)
	}
}

// parseEmailFile parses a .msg or .eml file and extracts email security information
func parseEmailFile(filename string, includeRawHeaders bool) (*EmailSecurityReport, error) {
	// Validate file extension
	ext := strings.ToLower(filepath.Ext(filename))
	if ext != ".msg" && ext != ".eml" {
		return nil, eris.New("file must have .msg or .eml extension")
	}

	// Clean path and prevent traversal
	cleanPath := filepath.Clean(filename)

	// Check if path contains traversal attempts
	if strings.Contains(filename, "..") {
		return nil, eris.New("path traversal detected")
	}

	// Get absolute path
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return nil, eris.Wrap(err, "invalid file path")
	}

	// Open the .msg file
	f, err := os.Open(absPath)
	if err != nil {
		return nil, eris.Wrap(err, "failed to open MSG file")
	}
	defer func() { _ = f.Close() }()

	// Get file info for size
	stat, err := f.Stat()
	if err != nil {
		return nil, eris.Wrap(err, "failed to stat MSG file")
	}

	// Verify it's a regular file
	if !stat.Mode().IsRegular() {
		return nil, eris.New("not a regular file")
	}

	// Validate file size before processing
	if stat.Size() > MaxFileSizeBytes {
		return nil, eris.Errorf("file size %d exceeds maximum allowed size of %d bytes (50MB)",
			stat.Size(), MaxFileSizeBytes)
	}
	if stat.Size() < 0 {
		return nil, eris.New("invalid negative file size")
	}

	var emailData []byte

	// EML files are already RFC822 format - read directly
	// MSG files need extraction from binary format
	if ext == ".eml" {
		// Read EML file directly (already RFC822 format)
		limitReader := io.LimitReader(f, MaxFileSizeBytes)
		emailData, err = io.ReadAll(limitReader)
		if err != nil {
			return nil, eris.Wrap(err, "failed to read EML file")
		}
	} else {
		// MSG file processing - verify format and extract
		// Verify file magic bytes for OLE/CFBF or ZIP format
		magic := make([]byte, 8)
		if _, err := f.Read(magic); err != nil {
			return nil, eris.Wrap(err, "failed to read file header")
		}

		// Check for CFBF signature (D0 CF 11 E0 A1 B1 1A E1)
		// or ZIP signature (50 4B 03 04 or 50 4B 05 06)
		isCFBF := len(magic) >= 8 && bytes.Equal(magic, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
		isZIP := len(magic) >= 2 && magic[0] == 0x50 && magic[1] == 0x4B

		if !isCFBF && !isZIP {
			return nil, eris.New("file is not a valid .msg format (invalid file signature)")
		}

		// Seek back to start
		if _, err := f.Seek(0, 0); err != nil {
			return nil, eris.Wrap(err, "failed to seek file")
		}

		// Try to extract email content from MSG file
		// MSG files are OLE/CFBF format, but we'll try a simpler approach first
		// by looking for embedded RFC822 message
		emailData, err = extractEmailFromMsg(f, stat.Size())
		if err != nil {
			return nil, eris.Wrap(err, "failed to extract email from MSG file")
		}
	}

	// Parse the email
	return parseEmail(emailData, includeRawHeaders)
}

// extractEmailFromMsg attempts to extract RFC822 email data from .msg file
// .msg files can contain the email in various formats, we'll try common approaches
func extractEmailFromMsg(r io.ReaderAt, size int64) ([]byte, error) {
	// Strategy 1: Try to open as a ZIP file (some .msg files are ZIP-based)
	zr, err := zip.NewReader(r, size)
	if err == nil {
		// Check number of files in ZIP to prevent zip bombs
		if len(zr.File) > MaxZipFiles {
			return nil, eris.Errorf("zip contains too many files: %d (max %d)", len(zr.File), MaxZipFiles)
		}

		// Look for email content in the ZIP
		for _, f := range zr.File {
			// Check compression ratio to detect zip bombs
			if f.UncompressedSize64 > 0 && f.CompressedSize64 > 0 {
				ratio := f.UncompressedSize64 / f.CompressedSize64
				if ratio > MaxCompressionRatio {
					return nil, eris.Errorf("suspicious compression ratio detected: %d:1 (max %d:1)",
						ratio, MaxCompressionRatio)
				}
			}

			// Check uncompressed size
			if f.UncompressedSize64 > MaxUncompressedSize {
				return nil, eris.Errorf("uncompressed file too large: %d bytes (max %d)",
					f.UncompressedSize64, MaxUncompressedSize)
			}

			// Common locations for email content in ZIP-based MSG
			if strings.Contains(strings.ToLower(f.Name), "message") ||
				strings.HasSuffix(strings.ToLower(f.Name), ".eml") {

				rc, err := f.Open()
				if err != nil {
					continue
				}
				// Use anonymous function for proper defer scoping
				data, err := func() ([]byte, error) {
					defer func() { _ = rc.Close() }()
					// Limit read size to prevent excessive memory use
					limitReader := io.LimitReader(rc, MaxUncompressedSize)
					return io.ReadAll(limitReader)
				}()
				if err != nil {
					continue
				}

				// Check if it looks like an email
				if bytes.Contains(data, []byte("From:")) && bytes.Contains(data, []byte("Subject:")) {
					return data, nil
				}
			}
		}
	}

	// Strategy 2: Read the entire file and search for embedded RFC822 headers
	// This is a fallback that works for some MSG formats
	data := make([]byte, size)
	n, err := r.ReadAt(data, 0)
	if err != nil && err != io.EOF {
		return nil, eris.Wrap(err, "failed to read MSG file")
	}
	data = data[:n]

	// Look for RFC822 email headers in the binary data
	// MSG files often contain the internet headers as a property
	emailContent := extractRFC822FromBinary(data)
	if emailContent != nil {
		return emailContent, nil
	}

	// Strategy 3: Try to find MIME headers directly
	// Some MSG files have embedded EML content
	if idx := bytes.Index(data, []byte("Return-Path:")); idx != -1 {
		return data[idx:], nil
	}
	if idx := bytes.Index(data, []byte("Received:")); idx != -1 {
		return data[idx:], nil
	}
	if idx := bytes.Index(data, []byte("From:")); idx != -1 && idx < 1000 {
		return data[idx:], nil
	}

	return nil, eris.New("could not find RFC822 email headers in MSG file")
}

// extractRFC822FromBinary searches for RFC822 email content in binary MSG data
func extractRFC822FromBinary(data []byte) []byte {
	// .msg files store the Internet Headers in a specific property
	// We'll search for the start of email headers and extract them

	// Strategy 1: Look for "Received:" which is typically the first header in transport messages
	receivedIdx := bytes.Index(data, []byte("Received:"))
	if receivedIdx != -1 && receivedIdx < 200000 {
		// Found it! Now let's extract from here to the end of headers
		// Headers end with a blank line (double newline)
		start := receivedIdx

		// Try to find where headers end
		// Look for double newline patterns
		end := len(data)
		searchStart := start
		iterations := 0
		// Use MaxHeaderSearchBytes to prevent excessive searching
		for searchStart < len(data)-4 && (searchStart-start) < MaxHeaderSearchBytes {
			// Add iteration counter to prevent infinite loops
			if iterations >= MaxHeaderSearchBytes {
				break
			}
			iterations++

			// Check for various double-newline patterns
			if searchStart+3 < len(data) &&
				data[searchStart] == '\r' && data[searchStart+1] == '\n' &&
				data[searchStart+2] == '\r' && data[searchStart+3] == '\n' {
				end = searchStart + 4
				break
			}
			if searchStart+1 < len(data) &&
				data[searchStart] == '\n' && data[searchStart+1] == '\n' {
				end = searchStart + 2
				break
			}
			searchStart++
		}

		headerData := data[start:min(end, len(data))]

		// Clean up the extracted headers - remove null bytes and invalid characters
		cleanedHeaders := bytes.ReplaceAll(headerData, []byte{0}, []byte{})

		// Verify we have valid headers
		if bytes.Contains(cleanedHeaders, []byte("From:")) ||
			bytes.Contains(cleanedHeaders, []byte("Subject:")) {
			return cleanedHeaders
		}
	}

	// Strategy 2: Look for "Return-Path:" which can be at the start
	returnPathIdx := bytes.Index(data, []byte("Return-Path:"))
	if returnPathIdx != -1 && returnPathIdx < 200000 {
		start := returnPathIdx
		end := len(data)
		searchStart := start
		iterations := 0

		for searchStart < len(data)-4 && (searchStart-start) < MaxHeaderSearchBytes {
			if iterations >= MaxHeaderSearchBytes {
				break
			}
			iterations++

			if searchStart+3 < len(data) &&
				data[searchStart] == '\r' && data[searchStart+1] == '\n' &&
				data[searchStart+2] == '\r' && data[searchStart+3] == '\n' {
				end = searchStart + 4
				break
			}
			if searchStart+1 < len(data) &&
				data[searchStart] == '\n' && data[searchStart+1] == '\n' {
				end = searchStart + 2
				break
			}
			searchStart++
		}

		headerData := data[start:min(end, len(data))]
		cleanedHeaders := bytes.ReplaceAll(headerData, []byte{0}, []byte{})

		if bytes.Contains(cleanedHeaders, []byte("From:")) ||
			bytes.Contains(cleanedHeaders, []byte("Subject:")) {
			return cleanedHeaders
		}
	}

	// Strategy 3: Look for "Authentication-Results:" which contains security info
	authResultsIdx := bytes.Index(data, []byte("Authentication-Results:"))
	if authResultsIdx != -1 && authResultsIdx < 200000 {
		// Found auth results, try to extract surrounding headers
		// Walk backwards to find the start of headers
		start := authResultsIdx
		for start > 0 && start > authResultsIdx-10000 {
			// Look for "Received:" which is typically first
			if start >= 9 && bytes.Equal(data[start-9:start], []byte("Received:")) {
				start = start - 9
				break
			}
			if start >= 12 && bytes.Equal(data[start-12:start], []byte("Return-Path:")) {
				start = start - 12
				break
			}
			start--
		}

		// Find end of headers
		end := len(data)
		searchStart := authResultsIdx
		iterations := 0

		for searchStart < len(data)-4 && (searchStart-start) < MaxHeaderSearchBytes {
			if iterations >= MaxHeaderSearchBytes {
				break
			}
			iterations++

			if searchStart+3 < len(data) &&
				data[searchStart] == '\r' && data[searchStart+1] == '\n' &&
				data[searchStart+2] == '\r' && data[searchStart+3] == '\n' {
				end = searchStart + 4
				break
			}
			if searchStart+1 < len(data) &&
				data[searchStart] == '\n' && data[searchStart+1] == '\n' {
				end = searchStart + 2
				break
			}
			searchStart++
		}

		headerData := data[start:min(end, len(data))]
		cleanedHeaders := bytes.ReplaceAll(headerData, []byte{0}, []byte{})

		if bytes.Contains(cleanedHeaders, []byte("From:")) ||
			bytes.Contains(cleanedHeaders, []byte("Authentication-Results:")) {
			return cleanedHeaders
		}
	}

	return nil
}

// sanitizeHeader removes control characters and prevents header injection
func sanitizeHeader(value string) string {
	// Remove all CR/LF characters to prevent header injection
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", "")

	// Remove control characters except tab
	value = strings.Map(func(r rune) rune {
		if r < 32 && r != '\t' {
			return -1
		}
		return r
	}, value)

	// Limit length to prevent buffer issues
	if len(value) > MaxHeaderLength {
		value = value[:MaxHeaderLength]
	}

	return strings.TrimSpace(value)
}

// parseEmail parses RFC822 email data and extracts security headers
func parseEmail(data []byte, includeRawHeaders bool) (*EmailSecurityReport, error) {
	// Parse as RFC822 message
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		// Try to clean up the data and parse again
		cleanData := cleanEmailData(data)
		msg, err = mail.ReadMessage(bytes.NewReader(cleanData))
		if err != nil {
			return nil, eris.Wrap(err, "failed to parse email message")
		}
	}

	report := &EmailSecurityReport{
		From:      sanitizeHeader(msg.Header.Get("From")),
		To:        sanitizeHeader(msg.Header.Get("To")),
		Subject:   sanitizeHeader(msg.Header.Get("Subject")),
		Date:      sanitizeHeader(msg.Header.Get("Date")),
		MessageID: sanitizeHeader(msg.Header.Get("Message-ID")),
	}

	if includeRawHeaders {
		report.RawHeaders = make(map[string][]string)
		for k, v := range msg.Header {
			report.RawHeaders[k] = v
		}
	}

	// Extract SPF results
	report.SPFResults = extractSPFResults(msg.Header)
	report.ReceivedSPF = msg.Header.Get("Received-SPF")

	// Extract DKIM results
	report.DKIMResults = extractDKIMResults(msg.Header)

	// Extract DMARC results
	report.DMARCResults = extractDMARCResults(msg.Header)

	// Parse Authentication-Results headers
	report.AuthResults = parseAuthenticationResults(msg.Header)

	// Extract ARC results
	report.ARCResults = extractARCResults(msg.Header)

	// Extract SCL (Spam Confidence Level) results
	report.SCL = extractSCLResults(msg.Header)

	return report, nil
}

// cleanEmailData attempts to clean up malformed email data
func cleanEmailData(data []byte) []byte {
	// Remove null bytes
	data = bytes.ReplaceAll(data, []byte{0}, []byte{})

	// Ensure headers end with double newline
	if !bytes.Contains(data[:min(len(data), 5000)], []byte("\n\n")) &&
		!bytes.Contains(data[:min(len(data), 5000)], []byte("\r\n\r\n")) {
		// Try to find where headers might end
		lines := bytes.Split(data, []byte("\n"))
		for i, line := range lines {
			if len(bytes.TrimSpace(line)) == 0 ||
				(!bytes.Contains(line, []byte(":")) && i > 5) {
				// Insert double newline here
				before := bytes.Join(lines[:i], []byte("\n"))
				after := bytes.Join(lines[i:], []byte("\n"))
				return append(append(before, []byte("\n\n")...), after...)
			}
		}
	}

	return data
}

// extractSPFResults extracts SPF authentication results from headers
func extractSPFResults(header mail.Header) []SPFResult {
	var results []SPFResult

	// Check Received-SPF header
	receivedSPF := header.Get("Received-SPF")

	// Validate header length
	if len(receivedSPF) > MaxHeaderLength {
		log.Printf("Warning: Received-SPF header exceeds maximum length, truncating")
		receivedSPF = receivedSPF[:MaxHeaderLength]
	}

	if receivedSPF != "" {
		result := parseSPFHeader(receivedSPF)
		if result != nil {
			results = append(results, *result)
		}
	}

	// Also check Authentication-Results for SPF
	authResults := header["Authentication-Results"]
	for _, ar := range authResults {
		// Validate header length
		if len(ar) > MaxHeaderLength {
			log.Printf("Warning: Authentication-Results header exceeds maximum length, truncating")
			ar = ar[:MaxHeaderLength]
		}
		spfResults := parseAuthResultsForSPF(ar)
		results = append(results, spfResults...)
	}

	return results
}

// parseSPFHeader parses a Received-SPF header
func parseSPFHeader(header string) *SPFResult {
	result := &SPFResult{}

	// Extract result (first word)
	parts := strings.Fields(header)
	if len(parts) > 0 {
		result.Result = strings.ToLower(strings.TrimSuffix(parts[0], ";"))
	}

	// Extract domain
	if match := regexp.MustCompile(`domain=([^\s;]+)`).FindStringSubmatch(header); len(match) > 1 {
		result.Domain = match[1]
	}

	// Extract client IP
	if match := regexp.MustCompile(`client-ip=([^\s;]+)`).FindStringSubmatch(header); len(match) > 1 {
		result.ClientIP = match[1]
	}

	// Extract explanation
	result.Explanation = strings.TrimSpace(header)

	return result
}

// parseAuthResultsForSPF extracts SPF results from Authentication-Results header
func parseAuthResultsForSPF(authResult string) []SPFResult {
	var results []SPFResult

	// Look for spf=result pattern with limited matches to prevent ReDoS
	spfRegex := regexp.MustCompile(`spf=([a-z]+)(?:\s+\(([^)]+)\))?`)
	matches := spfRegex.FindAllStringSubmatch(authResult, MaxRegexMatches)

	for _, match := range matches {
		result := SPFResult{
			Result: match[1],
		}
		if len(match) > 2 {
			result.Explanation = match[2]
		}

		// Extract domain from the context
		if domainMatch := regexp.MustCompile(`smtp\.mailfrom=([^\s;]+)`).FindStringSubmatch(authResult); len(domainMatch) > 1 {
			result.Domain = domainMatch[1]
		}

		results = append(results, result)
	}

	return results
}

// extractDKIMResults extracts DKIM signature information and validation results
func extractDKIMResults(header mail.Header) []DKIMResult {
	var results []DKIMResult

	// Parse DKIM-Signature headers
	dkimSigs := header["Dkim-Signature"]
	for _, sig := range dkimSigs {
		result := parseDKIMSignature(sig)
		if result != nil {
			results = append(results, *result)
		}
	}

	// Also check Authentication-Results for DKIM validation
	authResults := header["Authentication-Results"]
	for _, ar := range authResults {
		dkimResults := parseAuthResultsForDKIM(ar)

		// Merge with signature info if available
		for i := range dkimResults {
			// Try to find matching signature
			for j := range results {
				if results[j].Domain == dkimResults[i].Domain {
					// Update result status
					if dkimResults[i].Result != "" {
						results[j].Result = dkimResults[i].Result
					}
					break
				}
			}
			// If no match, add as new result
			if dkimResults[i].Result != "" {
				found := false
				for j := range results {
					if results[j].Domain == dkimResults[i].Domain {
						found = true
						break
					}
				}
				if !found {
					results = append(results, dkimResults[i])
				}
			}
		}
	}

	return results
}

// parseDKIMSignature parses a DKIM-Signature header
func parseDKIMSignature(sig string) *DKIMResult {
	result := &DKIMResult{
		Signature: sig,
	}

	// Parse d= (domain)
	if match := regexp.MustCompile(`d=([^\s;]+)`).FindStringSubmatch(sig); len(match) > 1 {
		result.Domain = match[1]
		result.HeaderD = match[1]
	}

	// Parse s= (selector)
	if match := regexp.MustCompile(`s=([^\s;]+)`).FindStringSubmatch(sig); len(match) > 1 {
		result.Selector = match[1]
		result.HeaderS = match[1]
	}

	// Parse a= (algorithm)
	if match := regexp.MustCompile(`a=([^\s;]+)`).FindStringSubmatch(sig); len(match) > 1 {
		result.HeaderA = match[1]
	}

	return result
}

// parseAuthResultsForDKIM extracts DKIM results from Authentication-Results header
func parseAuthResultsForDKIM(authResult string) []DKIMResult {
	var results []DKIMResult

	// Look for dkim=result pattern with limited matches to prevent ReDoS
	dkimRegex := regexp.MustCompile(`dkim=([a-z]+)(?:\s+\(([^)]+)\))?`)
	matches := dkimRegex.FindAllStringSubmatch(authResult, MaxRegexMatches)

	for _, match := range matches {
		result := DKIMResult{
			Result: match[1],
		}

		// Extract domain from header.d
		if domainMatch := regexp.MustCompile(`header\.d=([^\s;]+)`).FindStringSubmatch(authResult); len(domainMatch) > 1 {
			result.Domain = domainMatch[1]
		}

		// Extract selector from header.s
		if selectorMatch := regexp.MustCompile(`header\.s=([^\s;]+)`).FindStringSubmatch(authResult); len(selectorMatch) > 1 {
			result.Selector = selectorMatch[1]
		}

		results = append(results, result)
	}

	return results
}

// extractDMARCResults extracts DMARC evaluation results from headers
func extractDMARCResults(header mail.Header) []DMARCResult {
	var results []DMARCResult

	// Check Authentication-Results for DMARC
	authResults := header["Authentication-Results"]
	for _, ar := range authResults {
		dmarcResults := parseAuthResultsForDMARC(ar)
		results = append(results, dmarcResults...)
	}

	return results
}

// parseAuthResultsForDMARC extracts DMARC results from Authentication-Results header
func parseAuthResultsForDMARC(authResult string) []DMARCResult {
	var results []DMARCResult

	// Look for dmarc=result pattern with limited matches to prevent ReDoS
	dmarcRegex := regexp.MustCompile(`dmarc=([a-z]+)(?:\s+\(([^)]+)\))?`)
	matches := dmarcRegex.FindAllStringSubmatch(authResult, MaxRegexMatches)

	for _, match := range matches {
		result := DMARCResult{
			Result: match[1],
		}

		// Extract policy
		if policyMatch := regexp.MustCompile(`policy\.([a-z-]+)=([^\s;]+)`).FindStringSubmatch(authResult); len(policyMatch) > 2 {
			if policyMatch[1] == "dmarc" || policyMatch[1] == "policy" {
				result.Policy = policyMatch[2]
			}
		}

		// Alternative policy extraction
		if result.Policy == "" {
			if policyMatch := regexp.MustCompile(`p=([^\s;]+)`).FindStringSubmatch(authResult); len(policyMatch) > 1 {
				result.Policy = policyMatch[1]
			}
		}

		// Extract disposition
		if dispMatch := regexp.MustCompile(`action=([^\s;]+)`).FindStringSubmatch(authResult); len(dispMatch) > 1 {
			result.Disposition = dispMatch[1]
		}

		// Extract domain
		if domainMatch := regexp.MustCompile(`header\.from=([^\s;]+)`).FindStringSubmatch(authResult); len(domainMatch) > 1 {
			result.Domain = domainMatch[1]
		}

		results = append(results, result)
	}

	return results
}

// parseAuthenticationResults parses Authentication-Results headers comprehensively
func parseAuthenticationResults(header mail.Header) []AuthResult {
	var results []AuthResult

	authHeaders := header["Authentication-Results"]
	for _, ah := range authHeaders {
		result := parseAuthResultHeader(ah)
		if result != nil {
			results = append(results, *result)
		}
	}

	return results
}

// parseAuthResultHeader parses a single Authentication-Results header
func parseAuthResultHeader(header string) *AuthResult {
	result := &AuthResult{
		Methods: []AuthMethod{},
	}

	// Extract authserv-id (first component before semicolon)
	parts := strings.SplitN(header, ";", 2)
	if len(parts) > 0 {
		result.AuthServID = strings.TrimSpace(parts[0])
	}

	if len(parts) < 2 {
		return result
	}

	// Parse method results
	methodsStr := parts[1]

	// Split by method types
	methods := []string{"spf", "dkim", "dmarc", "arc"}
	for _, method := range methods {
		// Find all occurrences of this method with limited matches to prevent ReDoS
		methodRegex := regexp.MustCompile(method + `=([a-z]+)(?:\s+([^;]+))?`)
		matches := methodRegex.FindAllStringSubmatch(methodsStr, MaxRegexMatches)

		for _, match := range matches {
			authMethod := AuthMethod{
				Method:     method,
				Result:     match[1],
				Properties: make(map[string]string),
			}

			// Parse properties
			if len(match) > 2 && match[2] != "" {
				props := strings.Fields(match[2])
				for _, prop := range props {
					if strings.Contains(prop, "=") {
						kv := strings.SplitN(prop, "=", 2)
						authMethod.Properties[kv[0]] = kv[1]
					}
				}
			}

			result.Methods = append(result.Methods, authMethod)
		}
	}

	return result
}

// extractARCResults extracts ARC (Authenticated Received Chain) results
func extractARCResults(header mail.Header) []ARCResult {
	var results []ARCResult

	// Check for ARC-Authentication-Results headers
	arcAuthResults := header["Arc-Authentication-Results"]
	for _, ar := range arcAuthResults {
		result := parseARCHeader(ar)
		if result != nil {
			results = append(results, *result)
		}
	}

	// Check Authentication-Results for ARC chain validation
	authResults := header["Authentication-Results"]
	for _, ar := range authResults {
		arcChainResult := parseAuthResultsForARC(ar)
		if arcChainResult != nil {
			results = append(results, *arcChainResult)
		}
	}

	return results
}

// parseARCHeader parses an ARC-Authentication-Results header
func parseARCHeader(header string) *ARCResult {
	result := &ARCResult{}

	// Extract i= (instance)
	if match := regexp.MustCompile(`i=(\d+)`).FindStringSubmatch(header); len(match) > 1 {
		if instance, err := strconv.Atoi(match[1]); err == nil {
			result.Instance = instance
		}
	}

	return result
}

// parseAuthResultsForARC extracts ARC chain validation from Authentication-Results
func parseAuthResultsForARC(authResult string) *ARCResult {
	// Look for arc=result pattern
	arcRegex := regexp.MustCompile(`arc=([a-z]+)`)
	matches := arcRegex.FindStringSubmatch(authResult)

	if len(matches) > 1 {
		result := &ARCResult{
			Result: matches[1],
			Chain:  matches[1],
		}
		return result
	}

	return nil
}

// extractSCLResults extracts Microsoft Spam Confidence Level from X-Forefront-Antispam-Report headers
//
// SECURITY NOTE: X-Forefront-Antispam-Report headers can be spoofed by attackers.
// This header should ONLY be trusted when the email is received from authenticated
// Microsoft Exchange Online servers. Always verify the Received headers and
// authentication results (SPF/DKIM/DMARC) to ensure the email actually originated
// from Microsoft infrastructure before trusting the SCL score for security decisions.
func extractSCLResults(header mail.Header) *SCLResult {
	// Check X-Forefront-Antispam-Report header (trusted)
	forefrontReport := header.Get("X-Forefront-Antispam-Report")
	if forefrontReport != "" {
		// Validate header length
		if len(forefrontReport) > MaxHeaderLength {
			log.Printf("Warning: X-Forefront-Antispam-Report header exceeds maximum length, truncating")
			forefrontReport = forefrontReport[:MaxHeaderLength]
		}

		result := parseSCLHeader(forefrontReport, "X-Forefront-Antispam-Report")
		if result != nil {
			return result
		}
	}

	// Check X-Forefront-Antispam-Report-Untrusted header (alternative source)
	forefrontUntrusted := header.Get("X-Forefront-Antispam-Report-Untrusted")
	if forefrontUntrusted != "" {
		// Validate header length
		if len(forefrontUntrusted) > MaxHeaderLength {
			log.Printf("Warning: X-Forefront-Antispam-Report-Untrusted header exceeds maximum length, truncating")
			forefrontUntrusted = forefrontUntrusted[:MaxHeaderLength]
		}

		result := parseSCLHeader(forefrontUntrusted, "X-Forefront-Antispam-Report-Untrusted")
		if result != nil {
			return result
		}
	}

	return nil
}

// parseSCLHeader parses SCL value from X-Forefront-Antispam-Report header
func parseSCLHeader(header string, headerSource string) *SCLResult {
	// Use regex to extract SCL:value pattern
	// Pattern is safe from ReDoS: simple literal + digit capture group with no backtracking
	sclRegex := regexp.MustCompile(`SCL:(-?\d+)`)
	matches := sclRegex.FindStringSubmatch(header)

	if len(matches) > 1 {
		// Use strconv.Atoi for robust integer parsing with proper error handling
		score, err := strconv.Atoi(matches[1])
		if err != nil {
			log.Printf("Warning: Failed to parse SCL score from value '%s': %v", matches[1], err)
			return nil
		}

		// Validate score range - reject out-of-range values
		// Microsoft SCL valid range is -1 to 9
		if score < -1 || score > 9 {
			log.Printf("Warning: SCL score %d out of valid range [-1, 9], rejecting value", score)
			return nil
		}

		result := &SCLResult{
			Score:        score,
			Description:  getSCLDescription(score),
			HeaderSource: sanitizeHeader(headerSource),
			RawHeader:    sanitizeHeader(header),
		}

		return result
	}

	return nil
}

// getSCLDescription returns a human-readable description for an SCL score
func getSCLDescription(score int) string {
	switch score {
	case -1:
		return "Skipped spam filtering (safe sender or SCL override)"
	case 0, 1:
		return "Not spam"
	case 5, 6:
		return "Spam"
	case 7, 8, 9:
		return "High confidence spam"
	default:
		if score >= 2 && score <= 4 {
			return "Low spam probability"
		}
		return "Unknown spam confidence level"
	}
}

// outputJSON outputs the report as JSON
func outputJSON(report *EmailSecurityReport) {
	// Sanitize raw headers if present
	if report.RawHeaders != nil {
		sanitized := make(map[string][]string)
		for k, values := range report.RawHeaders {
			sanitizedValues := make([]string, len(values))
			for i, v := range values {
				// Ensure UTF-8 validity
				sanitizedValues[i] = strings.ToValidUTF8(v, "�")
			}
			sanitized[strings.ToValidUTF8(k, "�")] = sanitizedValues
		}
		report.RawHeaders = sanitized
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(report); err != nil {
		log.Printf("Error encoding JSON: %v", err)
		os.Exit(1)
	}
}

// outputText outputs the report in human-readable text format
func outputText(report *EmailSecurityReport, verbose bool) {
	fmt.Println("=" + strings.Repeat("=", 79))
	fmt.Println("EMAIL SECURITY ANALYSIS REPORT")
	fmt.Println("=" + strings.Repeat("=", 79))
	fmt.Println()

	// Basic Email Information
	fmt.Println("EMAIL INFORMATION")
	fmt.Println("-" + strings.Repeat("-", 79))
	fmt.Printf("From:       %s\n", report.From)
	fmt.Printf("To:         %s\n", report.To)
	fmt.Printf("Subject:    %s\n", report.Subject)
	fmt.Printf("Date:       %s\n", report.Date)
	fmt.Printf("Message-ID: %s\n", report.MessageID)
	fmt.Println()

	// SPF Results
	fmt.Println("SPF (SENDER POLICY FRAMEWORK) RESULTS")
	fmt.Println("-" + strings.Repeat("-", 79))
	fmt.Println("SPF validates that the sending server is authorized to send email for the domain.")
	fmt.Println()
	if len(report.SPFResults) > 0 {
		for i, spf := range report.SPFResults {
			fmt.Printf("SPF Check #%d:\n", i+1)
			fmt.Printf("  Result:     %s\n", formatResult(spf.Result))
			if spf.Domain != "" {
				fmt.Printf("  Domain:     %s\n", spf.Domain)
			}
			if spf.ClientIP != "" {
				fmt.Printf("  Client IP:  %s\n", spf.ClientIP)
			}
			if spf.Explanation != "" && verbose {
				fmt.Printf("  Details:    %s\n", spf.Explanation)
			}
			fmt.Println()
		}
	} else {
		fmt.Println("  No SPF results found")
		fmt.Println()
	}

	if report.ReceivedSPF != "" && verbose {
		fmt.Printf("Received-SPF Header:\n  %s\n\n", report.ReceivedSPF)
	}

	// DKIM Results
	fmt.Println("DKIM (DOMAINKEYS IDENTIFIED MAIL) RESULTS")
	fmt.Println("-" + strings.Repeat("-", 79))
	fmt.Println("DKIM uses cryptographic signatures to verify email authenticity and integrity.")
	fmt.Println()
	if len(report.DKIMResults) > 0 {
		for i, dkim := range report.DKIMResults {
			fmt.Printf("DKIM Signature #%d:\n", i+1)
			if dkim.Result != "" {
				fmt.Printf("  Result:     %s\n", formatResult(dkim.Result))
			}
			if dkim.Domain != "" {
				fmt.Printf("  Domain:     %s\n", dkim.Domain)
			}
			if dkim.Selector != "" {
				fmt.Printf("  Selector:   %s\n", dkim.Selector)
			}
			if dkim.HeaderA != "" {
				fmt.Printf("  Algorithm:  %s\n", dkim.HeaderA)
			}
			if verbose && dkim.Signature != "" {
				fmt.Printf("  Signature:  %s...\n", truncate(dkim.Signature, 60))
			}
			fmt.Println()
		}
	} else {
		fmt.Println("  No DKIM signatures found")
		fmt.Println()
	}

	// DMARC Results
	fmt.Println("DMARC (DOMAIN MESSAGE AUTHENTICATION REPORTING & CONFORMANCE) RESULTS")
	fmt.Println("-" + strings.Repeat("-", 79))
	fmt.Println("DMARC builds on SPF and DKIM to specify how to handle authentication failures.")
	fmt.Println()
	if len(report.DMARCResults) > 0 {
		for i, dmarc := range report.DMARCResults {
			fmt.Printf("DMARC Check #%d:\n", i+1)
			fmt.Printf("  Result:      %s\n", formatResult(dmarc.Result))
			if dmarc.Policy != "" {
				fmt.Printf("  Policy:      %s\n", dmarc.Policy)
			}
			if dmarc.Domain != "" {
				fmt.Printf("  Domain:      %s\n", dmarc.Domain)
			}
			if dmarc.Disposition != "" {
				fmt.Printf("  Disposition: %s\n", dmarc.Disposition)
			}
			if dmarc.SPFAlignment != "" {
				fmt.Printf("  SPF Align:   %s\n", formatResult(dmarc.SPFAlignment))
			}
			if dmarc.DKIMAlignment != "" {
				fmt.Printf("  DKIM Align:  %s\n", formatResult(dmarc.DKIMAlignment))
			}
			fmt.Println()
		}
	} else {
		fmt.Println("  No DMARC results found")
		fmt.Println()
	}

	// ARC Results
	if len(report.ARCResults) > 0 {
		fmt.Println("ARC (AUTHENTICATED RECEIVED CHAIN) RESULTS")
		fmt.Println("-" + strings.Repeat("-", 79))
		fmt.Println("ARC preserves authentication results across email forwarding.")
		fmt.Println()
		for i, arc := range report.ARCResults {
			fmt.Printf("ARC Chain #%d:\n", i+1)
			if arc.Instance > 0 {
				fmt.Printf("  Instance: %d\n", arc.Instance)
			}
			if arc.Result != "" {
				fmt.Printf("  Result:   %s\n", formatResult(arc.Result))
			}
			if arc.Chain != "" {
				fmt.Printf("  Chain:    %s\n", formatResult(arc.Chain))
			}
			fmt.Println()
		}
	}

	// SCL Results
	if report.SCL != nil {
		fmt.Println("SCL (SPAM CONFIDENCE LEVEL) RESULTS")
		fmt.Println("-" + strings.Repeat("-", 79))
		fmt.Println("Microsoft's Spam Confidence Level indicates the likelihood of spam.")
		fmt.Println()
		fmt.Printf("SCL Score:   %d\n", report.SCL.Score)
		fmt.Printf("Assessment:  %s\n", report.SCL.Description)
		fmt.Printf("Source:      %s\n", report.SCL.HeaderSource)
		if verbose && report.SCL.RawHeader != "" {
			fmt.Printf("Raw Header:  %s\n", truncate(report.SCL.RawHeader, 80))
		}
		fmt.Println()
	}

	// Authentication Results Summary
	if len(report.AuthResults) > 0 && verbose {
		fmt.Println("AUTHENTICATION-RESULTS HEADERS")
		fmt.Println("-" + strings.Repeat("-", 79))
		for i, ar := range report.AuthResults {
			fmt.Printf("Auth Server #%d: %s\n", i+1, ar.AuthServID)
			for _, method := range ar.Methods {
				fmt.Printf("  %s: %s", strings.ToUpper(method.Method), formatResult(method.Result))
				if len(method.Properties) > 0 {
					fmt.Printf(" (")
					first := true
					for k, v := range method.Properties {
						if !first {
							fmt.Printf(", ")
						}
						fmt.Printf("%s=%s", k, v)
						first = false
					}
					fmt.Printf(")")
				}
				fmt.Println()
			}
			fmt.Println()
		}
	}

	// Raw Headers (if verbose)
	if verbose && report.RawHeaders != nil && len(report.RawHeaders) > 0 {
		fmt.Println("RAW EMAIL HEADERS")
		fmt.Println("-" + strings.Repeat("-", 79))
		for key, values := range report.RawHeaders {
			for _, value := range values {
				fmt.Printf("%s: %s\n", key, value)
			}
		}
		fmt.Println()
	}

	// Summary
	fmt.Println("SECURITY SUMMARY")
	fmt.Println("-" + strings.Repeat("-", 79))
	summarizeSecurity(report)
	fmt.Println()
	fmt.Println("=" + strings.Repeat("=", 79))
}

// formatResult formats a result string with color/styling indicators
func formatResult(result string) string {
	result = strings.ToUpper(result)
	switch result {
	case "PASS":
		return result + " ✓"
	case "FAIL":
		return result + " ✗"
	case "SOFTFAIL":
		return result + " ⚠"
	case "NEUTRAL":
		return result + " ~"
	case "NONE":
		return result + " ○"
	default:
		return result
	}
}

// truncate truncates a string to a maximum length
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// summarizeSecurity provides a security assessment summary
func summarizeSecurity(report *EmailSecurityReport) {
	spfPass := false
	dkimPass := false
	dmarcPass := false
	isSpam := false

	// Check SPF
	for _, spf := range report.SPFResults {
		if strings.ToLower(spf.Result) == "pass" {
			spfPass = true
			break
		}
	}

	// Check DKIM
	for _, dkim := range report.DKIMResults {
		if strings.ToLower(dkim.Result) == "pass" {
			dkimPass = true
			break
		}
	}

	// Check DMARC
	for _, dmarc := range report.DMARCResults {
		if strings.ToLower(dmarc.Result) == "pass" {
			dmarcPass = true
			break
		}
	}

	// Check SCL for spam
	if report.SCL != nil && report.SCL.Score >= 5 {
		isSpam = true
	}

	fmt.Printf("SPF Authentication:   %s\n", formatBool(spfPass))
	fmt.Printf("DKIM Authentication:  %s\n", formatBool(dkimPass))
	fmt.Printf("DMARC Authentication: %s\n", formatBool(dmarcPass))
	if report.SCL != nil {
		fmt.Printf("Spam Confidence (SCL): %d (%s)\n", report.SCL.Score, report.SCL.Description)
	}
	fmt.Println()

	// Overall assessment
	if isSpam {
		fmt.Println("Overall Assessment: SPAM DETECTED ✗")
		fmt.Printf("This email has a spam confidence level of %d. Exercise extreme caution.\n", report.SCL.Score)
	} else if spfPass && dkimPass && dmarcPass {
		fmt.Println("Overall Assessment: SECURE ✓")
		fmt.Println("This email passed all major authentication checks.")
	} else if spfPass || dkimPass {
		fmt.Println("Overall Assessment: PARTIALLY SECURE ⚠")
		fmt.Println("This email passed some authentication checks but not all.")
	} else {
		fmt.Println("Overall Assessment: INSECURE ✗")
		fmt.Println("This email failed authentication checks. Exercise caution.")
	}
}

// formatBool formats a boolean as a pass/fail string
func formatBool(b bool) string {
	if b {
		return "PASS ✓"
	}
	return "FAIL ✗"
}

// ============================================================================
// DMARC Aggregate Report Parsing Functions
// ============================================================================

// parseDMARCReportFile parses a DMARC aggregate report from file
// Supports .xml, .xml.gz, and .zip formats
func parseDMARCReportFile(filename string) (*DMARCAggregateReport, error) {
	// Validate file extension
	lowerName := strings.ToLower(filename)
	validExt := strings.HasSuffix(lowerName, ".xml") ||
		strings.HasSuffix(lowerName, ".xml.gz") ||
		strings.HasSuffix(lowerName, ".gz") ||
		strings.HasSuffix(lowerName, ".zip")

	if !validExt {
		return nil, eris.New("file must have .xml, .xml.gz, or .zip extension")
	}

	// Security: path validation (reuse existing pattern)
	cleanPath := filepath.Clean(filename)
	if strings.Contains(filename, "..") {
		return nil, eris.New("path traversal detected")
	}

	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return nil, eris.Wrap(err, "invalid file path")
	}

	f, err := os.Open(absPath)
	if err != nil {
		return nil, eris.Wrap(err, "failed to open DMARC report file")
	}
	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil {
		return nil, eris.Wrap(err, "failed to stat file")
	}

	if !stat.Mode().IsRegular() {
		return nil, eris.New("not a regular file")
	}

	if stat.Size() > MaxDMARCReportSize {
		return nil, eris.Errorf("file size %d exceeds maximum %d bytes", stat.Size(), MaxDMARCReportSize)
	}

	// Determine format and parse
	var reader io.Reader
	switch {
	case strings.HasSuffix(lowerName, ".xml.gz") || strings.HasSuffix(lowerName, ".gz"):
		gzReader, err := gzip.NewReader(f)
		if err != nil {
			return nil, eris.Wrap(err, "failed to create gzip reader")
		}
		defer func() { _ = gzReader.Close() }()
		reader = io.LimitReader(gzReader, MaxDMARCReportSize)

	case strings.HasSuffix(lowerName, ".zip"):
		xmlData, err := extractXMLFromDMARCZip(f, stat.Size())
		if err != nil {
			return nil, eris.Wrap(err, "failed to extract XML from ZIP")
		}
		reader = bytes.NewReader(xmlData)

	default: // .xml
		reader = io.LimitReader(f, MaxDMARCReportSize)
	}

	return parseDMARCReportSecure(reader)
}

// extractXMLFromDMARCZip safely extracts DMARC XML from a ZIP archive
func extractXMLFromDMARCZip(r io.ReaderAt, size int64) ([]byte, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, eris.Wrap(err, "failed to open ZIP archive")
	}

	// Check number of files
	if len(zr.File) > MaxZipFiles {
		return nil, eris.Errorf("zip contains too many files: %d (max %d)", len(zr.File), MaxZipFiles)
	}

	// Find XML file in the archive
	for _, f := range zr.File {
		// Check compression ratio
		if f.UncompressedSize64 > 0 && f.CompressedSize64 > 0 {
			ratio := f.UncompressedSize64 / f.CompressedSize64
			if ratio > MaxCompressionRatio {
				return nil, eris.Errorf("suspicious compression ratio: %d:1 (max %d:1)", ratio, MaxCompressionRatio)
			}
		}

		// Check uncompressed size
		if f.UncompressedSize64 > MaxUncompressedSize {
			return nil, eris.Errorf("uncompressed file too large: %d bytes (max %d)", f.UncompressedSize64, MaxUncompressedSize)
		}

		// Look for XML files
		if strings.HasSuffix(strings.ToLower(f.Name), ".xml") {
			rc, err := f.Open()
			if err != nil {
				continue
			}

			data, err := func() ([]byte, error) {
				defer func() { _ = rc.Close() }()
				limitReader := io.LimitReader(rc, MaxUncompressedSize)
				return io.ReadAll(limitReader)
			}()
			if err != nil {
				continue
			}

			// Verify it looks like a DMARC report
			if bytes.Contains(data, []byte("<feedback")) || bytes.Contains(data, []byte("<report_metadata")) {
				return data, nil
			}
		}
	}

	return nil, eris.New("no DMARC XML file found in ZIP archive")
}

// parseDMARCReportSecure parses DMARC XML with security controls
func parseDMARCReportSecure(r io.Reader) (*DMARCAggregateReport, error) {
	// Create decoder with XXE prevention
	decoder := xml.NewDecoder(r)
	decoder.Entity = make(map[string]string) // Disable external entities

	var report DMARCAggregateReport
	if err := decoder.Decode(&report); err != nil {
		return nil, eris.Wrap(err, "failed to parse DMARC XML")
	}

	// Validate parsed data
	if err := validateDMARCReport(&report); err != nil {
		return nil, err
	}

	return &report, nil
}

// validateDMARCReport performs security validation on parsed report
func validateDMARCReport(report *DMARCAggregateReport) error {
	// Validate record count
	if len(report.Records) > MaxRecordsPerReport {
		return eris.Errorf("report contains %d records, exceeds limit of %d",
			len(report.Records), MaxRecordsPerReport)
	}

	// Validate string lengths
	if len(report.Metadata.OrgName) > MaxStringLength {
		return eris.New("org_name exceeds maximum length")
	}
	if len(report.Metadata.ReportID) > MaxStringLength {
		return eris.New("report_id exceeds maximum length")
	}

	// Validate date range
	if report.Metadata.DateRange.Begin < 0 || report.Metadata.DateRange.End < 0 {
		return eris.New("invalid negative timestamp in date_range")
	}
	if report.Metadata.DateRange.End < report.Metadata.DateRange.Begin {
		return eris.New("date_range end is before begin")
	}

	// Validate each record
	for i := range report.Records {
		if err := validateDMARCRecord(&report.Records[i], i); err != nil {
			return err
		}
	}

	return nil
}

// validateDMARCRecord validates a single DMARC record
func validateDMARCRecord(record *DMARCAggregateRecord, index int) error {
	// Validate IP address format
	ip := net.ParseIP(record.Row.SourceIP)
	if ip == nil {
		return eris.Errorf("record %d: invalid source_ip: %s", index, record.Row.SourceIP)
	}

	// Validate count is positive and within bounds
	if record.Row.Count < 0 {
		return eris.Errorf("record %d: invalid negative count", index)
	}
	if record.Row.Count > MaxRecordCount {
		return eris.Errorf("record %d: count %d exceeds limit of %d", index, record.Row.Count, MaxRecordCount)
	}

	// Validate disposition value
	validDispositions := map[string]bool{"none": true, "quarantine": true, "reject": true, "": true}
	if !validDispositions[strings.ToLower(record.Row.PolicyEvaluated.Disposition)] {
		return eris.Errorf("record %d: invalid disposition: %s", index, record.Row.PolicyEvaluated.Disposition)
	}

	// Sanitize domain names
	record.Identifiers.HeaderFrom = sanitizeDMARCDomain(record.Identifiers.HeaderFrom)
	record.Identifiers.EnvelopeFrom = sanitizeDMARCDomain(record.Identifiers.EnvelopeFrom)
	record.Identifiers.EnvelopeTo = sanitizeDMARCDomain(record.Identifiers.EnvelopeTo)

	return nil
}

// sanitizeDMARCDomain removes potentially malicious characters from domain names
func sanitizeDMARCDomain(domain string) string {
	// Remove control characters
	domain = strings.Map(func(r rune) rune {
		if r < 32 {
			return -1
		}
		return r
	}, domain)

	// Limit length
	if len(domain) > 255 {
		domain = domain[:255]
	}

	return strings.TrimSpace(domain)
}

// sanitizeDMARCError provides user-safe error messages
func sanitizeDMARCError(err error) string {
	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "path traversal"):
		return "Invalid file path."
	case strings.Contains(errStr, "exceeds maximum") || strings.Contains(errStr, "exceeds limit"):
		return "File is too large."
	case strings.Contains(errStr, "failed to parse") || strings.Contains(errStr, "invalid"):
		return "File is not valid DMARC XML."
	case strings.Contains(errStr, "compression ratio"):
		return "File appears to be malformed (compression bomb detected)."
	case strings.Contains(errStr, "no DMARC XML"):
		return "No valid DMARC report found in archive."
	default:
		return "Please ensure the file is a valid DMARC aggregate report."
	}
}

// ============================================================================
// DMARC Report Analysis Functions
// ============================================================================

// analyzeDMARCReport performs forensic analysis on the parsed report
func analyzeDMARCReport(report *DMARCAggregateReport) *DMARCReportAnalysis {
	analysis := &DMARCReportAnalysis{
		DispositionStats: make(map[string]int),
	}

	// Aggregate counters
	var totalEmails, spfPass, dkimPass, bothPass int
	countryStats := make(map[string]*DMARCCountryStat)
	asnStats := make(map[uint]*DMARCASNStat)
	var failingSources []DMARCFailingSource

	for _, record := range report.Records {
		count := record.Row.Count
		totalEmails += count

		// Track disposition
		disp := strings.ToLower(record.Row.PolicyEvaluated.Disposition)
		if disp == "" {
			disp = "none"
		}
		analysis.DispositionStats[disp] += count

		// Track authentication results
		spfResult := strings.ToLower(record.Row.PolicyEvaluated.SPF)
		dkimResult := strings.ToLower(record.Row.PolicyEvaluated.DKIM)

		if spfResult == "pass" {
			spfPass += count
		}
		if dkimResult == "pass" {
			dkimPass += count
		}
		if spfResult == "pass" && dkimResult == "pass" {
			bothPass += count
		}

		// Aggregate by country and ASN if enrichment available
		if record.Enrichment != nil {
			cc := record.Enrichment.CountryCode
			if cc != "" {
				if _, ok := countryStats[cc]; !ok {
					countryStats[cc] = &DMARCCountryStat{
						Country:     record.Enrichment.Country,
						CountryCode: cc,
					}
				}
				countryStats[cc].EmailCount += count
				if spfResult != "pass" || dkimResult != "pass" {
					countryStats[cc].FailCount += count
				}
			}

			// ASN aggregation
			asn := record.Enrichment.ASN
			if asn != 0 {
				if _, ok := asnStats[asn]; !ok {
					asnStats[asn] = &DMARCASNStat{
						ASN:          asn,
						Organization: record.Enrichment.Organization,
					}
				}
				asnStats[asn].EmailCount += count
				if spfResult != "pass" || dkimResult != "pass" {
					asnStats[asn].FailCount += count
				}
			}
		}

		// Track failing sources
		if spfResult != "pass" || dkimResult != "pass" {
			reason := determineDMARCFailReason(record)
			fs := DMARCFailingSource{
				IP:         record.Row.SourceIP,
				FailCount:  count,
				FailReason: reason,
			}
			if record.Enrichment != nil {
				fs.Country = record.Enrichment.Country
				fs.Organization = record.Enrichment.Organization
			}
			failingSources = append(failingSources, fs)
		}
	}

	// Calculate rates
	analysis.TotalEmails = totalEmails
	if totalEmails > 0 {
		analysis.PassRate = float64(bothPass) / float64(totalEmails) * 100
		analysis.SPFPassRate = float64(spfPass) / float64(totalEmails) * 100
		analysis.DKIMPassRate = float64(dkimPass) / float64(totalEmails) * 100
	}

	// Sort and limit top countries
	analysis.TopSourceCountries = topNDMARCCountries(countryStats, 10)
	analysis.TopASNs = topNDMARCASNs(asnStats, 10)

	// Sort failing sources by count
	sort.Slice(failingSources, func(i, j int) bool {
		return failingSources[i].FailCount > failingSources[j].FailCount
	})
	if len(failingSources) > 10 {
		failingSources = failingSources[:10]
	}
	analysis.FailingSources = failingSources

	// Generate recommendations
	analysis.Recommendations = generateDMARCRecommendations(report, analysis)
	analysis.OverallThreatLevel = calculateDMARCOverallThreat(analysis)

	return analysis
}

// determineDMARCFailReason determines why a record failed authentication
func determineDMARCFailReason(record DMARCAggregateRecord) string {
	spf := strings.ToLower(record.Row.PolicyEvaluated.SPF)
	dkim := strings.ToLower(record.Row.PolicyEvaluated.DKIM)

	switch {
	case spf != "pass" && dkim != "pass":
		return "Both SPF and DKIM failed"
	case spf != "pass":
		return "SPF failed"
	case dkim != "pass":
		return "DKIM failed"
	default:
		return "Unknown"
	}
}

// topNDMARCCountries returns the top N countries by email count
func topNDMARCCountries(stats map[string]*DMARCCountryStat, n int) []DMARCCountryStat {
	var result []DMARCCountryStat
	for _, stat := range stats {
		result = append(result, *stat)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].EmailCount > result[j].EmailCount
	})
	if len(result) > n {
		result = result[:n]
	}
	return result
}

// topNDMARCASNs returns the top N ASNs by email count
func topNDMARCASNs(stats map[uint]*DMARCASNStat, n int) []DMARCASNStat {
	var result []DMARCASNStat
	for _, stat := range stats {
		result = append(result, *stat)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].EmailCount > result[j].EmailCount
	})
	if len(result) > n {
		result = result[:n]
	}
	return result
}

// generateDMARCRecommendations generates actionable recommendations based on analysis
func generateDMARCRecommendations(report *DMARCAggregateReport, analysis *DMARCReportAnalysis) []DMARCRecommendation {
	var recommendations []DMARCRecommendation

	// Check policy strength
	policy := strings.ToLower(report.PolicyPublished.Policy)
	if policy == "none" {
		recommendations = append(recommendations, DMARCRecommendation{
			Priority:    "high",
			Category:    "policy",
			Title:       "Upgrade DMARC Policy",
			Description: "Your DMARC policy is set to 'none', which only monitors but doesn't protect against spoofing.",
			Action:      "Consider upgrading to 'quarantine' or 'reject' policy after verifying all legitimate sources pass authentication.",
		})
	} else if policy == "quarantine" && analysis.PassRate >= 95 {
		recommendations = append(recommendations, DMARCRecommendation{
			Priority:    "medium",
			Category:    "policy",
			Title:       "Consider Reject Policy",
			Description: "Your pass rate is high enough to consider upgrading to 'reject' policy for maximum protection.",
			Action:      "Upgrade DMARC policy from 'quarantine' to 'reject' for stronger spoofing protection.",
		})
	}

	// Check percentage
	if report.PolicyPublished.Percentage < 100 && report.PolicyPublished.Percentage > 0 {
		recommendations = append(recommendations, DMARCRecommendation{
			Priority:    "medium",
			Category:    "policy",
			Title:       "Increase Policy Coverage",
			Description: fmt.Sprintf("Your DMARC policy only applies to %d%% of messages.", report.PolicyPublished.Percentage),
			Action:      "Gradually increase pct= value to 100 for full protection.",
		})
	}

	// Check SPF alignment
	if analysis.SPFPassRate < 90 && analysis.SPFPassRate > 0 {
		recommendations = append(recommendations, DMARCRecommendation{
			Priority:    "high",
			Category:    "spf",
			Title:       "Improve SPF Configuration",
			Description: fmt.Sprintf("SPF pass rate is only %.1f%%, indicating configuration issues.", analysis.SPFPassRate),
			Action:      "Review SPF records to ensure all legitimate sending sources are included.",
		})
	}

	// Check DKIM alignment
	if analysis.DKIMPassRate < 90 && analysis.DKIMPassRate > 0 {
		recommendations = append(recommendations, DMARCRecommendation{
			Priority:    "high",
			Category:    "dkim",
			Title:       "Improve DKIM Configuration",
			Description: fmt.Sprintf("DKIM pass rate is only %.1f%%, indicating signing issues.", analysis.DKIMPassRate),
			Action:      "Verify DKIM signing is enabled for all email sources and keys are properly published.",
		})
	}

	// Check for significant failures
	if len(analysis.FailingSources) > 5 {
		recommendations = append(recommendations, DMARCRecommendation{
			Priority:    "medium",
			Category:    "monitoring",
			Title:       "Investigate Failing Sources",
			Description: fmt.Sprintf("Found %d sources with authentication failures.", len(analysis.FailingSources)),
			Action:      "Review failing sources to identify if they are legitimate services that need configuration or potential spoofing attempts.",
		})
	}

	return recommendations
}

// calculateDMARCOverallThreat calculates the overall threat level
func calculateDMARCOverallThreat(analysis *DMARCReportAnalysis) string {
	// Calculate based on pass rate and failure volume
	if analysis.PassRate >= 95 {
		return "low"
	} else if analysis.PassRate >= 80 {
		return "medium"
	} else if analysis.PassRate >= 50 {
		return "high"
	}
	return "critical"
}

// ============================================================================
// DMARC IP Enrichment Functions
// ============================================================================

// enrichDMARCReport enriches the report with IP geolocation data
func enrichDMARCReport(report *DMARCAggregateReport, geoDBPath string) {
	// Try to find GeoIP database
	dbPaths := []string{geoDBPath}
	if geoDBPath == "" {
		// Check common locations
		dbPaths = []string{
			os.Getenv("GEOIP_DB_PATH"),
			"./GeoLite2-City.mmdb",
			"./data/GeoLite2-City.mmdb",
			"/usr/share/GeoIP/GeoLite2-City.mmdb",
			"/var/lib/GeoIP/GeoLite2-City.mmdb",
		}
	}

	var cityDB *geoip2.Reader
	for _, path := range dbPaths {
		if path == "" {
			continue
		}
		var err error
		cityDB, err = geoip2.Open(path)
		if err == nil {
			defer func() { _ = cityDB.Close() }()
			break
		}
	}

	// Try to open ASN database for autonomous system lookups
	// Note: ASN data requires a separate GeoLite2-ASN.mmdb database
	asnDBPaths := []string{
		os.Getenv("GEOIP_ASN_DB_PATH"),
		"./GeoLite2-ASN.mmdb",
		"./data/GeoLite2-ASN.mmdb",
		"/usr/share/GeoIP/GeoLite2-ASN.mmdb",
		"/var/lib/GeoIP/GeoLite2-ASN.mmdb",
	}
	var asnDB *geoip2.Reader
	for _, path := range asnDBPaths {
		if path == "" {
			continue
		}
		var err error
		asnDB, err = geoip2.Open(path)
		if err == nil {
			defer func() { _ = asnDB.Close() }()
			break
		}
	}

	// Calculate average volume for threat scoring
	var totalEmails int
	for _, record := range report.Records {
		totalEmails += record.Row.Count
	}
	avgVolume := 1.0
	if len(report.Records) > 0 {
		avgVolume = float64(totalEmails) / float64(len(report.Records))
	}

	// Enrich each record
	for i := range report.Records {
		ip := net.ParseIP(report.Records[i].Row.SourceIP)
		if ip == nil {
			continue
		}

		enrichment := &IPEnrichment{}

		// GeoIP City lookup if database available
		if cityDB != nil {
			record, err := cityDB.City(ip)
			if err == nil {
				enrichment.Country = record.Country.Names["en"]
				enrichment.CountryCode = record.Country.IsoCode
				if len(record.City.Names) > 0 {
					enrichment.City = record.City.Names["en"]
				}
			}
		}

		// ASN lookup requires separate GeoLite2-ASN database
		if asnDB != nil {
			asnRecord, err := asnDB.ASN(ip)
			if err == nil {
				enrichment.ASN = asnRecord.AutonomousSystemNumber
				enrichment.Organization = asnRecord.AutonomousSystemOrganization
			}
		}

		// Calculate threat score
		enrichment.ThreatScore = calculateDMARCThreatScore(&report.Records[i], avgVolume)
		enrichment.ThreatLevel = threatLevelFromScore(enrichment.ThreatScore)

		report.Records[i].Enrichment = enrichment
	}
}

// calculateDMARCThreatScore computes a risk score (0-100) for a DMARC record
func calculateDMARCThreatScore(record *DMARCAggregateRecord, avgVolume float64) float64 {
	score := 0.0

	// Authentication failures (0-40 points)
	if strings.ToLower(record.Row.PolicyEvaluated.SPF) != "pass" {
		score += 20
	}
	if strings.ToLower(record.Row.PolicyEvaluated.DKIM) != "pass" {
		score += 20
	}

	// Volume anomaly (0-30 points)
	if float64(record.Row.Count) > avgVolume*3 {
		score += 30
	} else if float64(record.Row.Count) > avgVolume*2 {
		score += 15
	}

	// Policy disposition (0-20 points)
	switch strings.ToLower(record.Row.PolicyEvaluated.Disposition) {
	case "reject":
		score += 20
	case "quarantine":
		score += 10
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// threatLevelFromScore converts a numeric score to threat level
func threatLevelFromScore(score float64) string {
	switch {
	case score >= 70:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 30:
		return "medium"
	default:
		return "low"
	}
}

// ============================================================================
// DMARC Output Functions
// ============================================================================

// outputDMARCJSON outputs the DMARC report as JSON
func outputDMARCJSON(report *DMARCAggregateReport) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(report); err != nil {
		log.Printf("Error encoding JSON: %v", err)
		os.Exit(1)
	}
}

// outputDMARCText outputs the DMARC report in human-readable text format
func outputDMARCText(report *DMARCAggregateReport, verbose bool) {
	fmt.Println("=" + strings.Repeat("=", 79))
	fmt.Println("DMARC AGGREGATE REPORT ANALYSIS")
	fmt.Println("=" + strings.Repeat("=", 79))
	fmt.Println()

	// Report Metadata
	fmt.Println("REPORT INFORMATION")
	fmt.Println("-" + strings.Repeat("-", 79))
	fmt.Printf("Organization:  %s\n", report.Metadata.OrgName)
	fmt.Printf("Report ID:     %s\n", report.Metadata.ReportID)
	fmt.Printf("Email:         %s\n", report.Metadata.Email)
	fmt.Printf("Period:        %s to %s\n",
		formatUnixTime(report.Metadata.DateRange.Begin),
		formatUnixTime(report.Metadata.DateRange.End))
	fmt.Println()

	// Policy Published
	fmt.Println("DOMAIN POLICY")
	fmt.Println("-" + strings.Repeat("-", 79))
	fmt.Printf("Domain:        %s\n", report.PolicyPublished.Domain)
	fmt.Printf("Policy (p):    %s\n", formatDMARCPolicy(report.PolicyPublished.Policy))
	fmt.Printf("Subdomain (sp): %s\n", formatDMARCPolicy(report.PolicyPublished.SubdomainPolicy))
	fmt.Printf("DKIM Align:    %s\n", formatDMARCAlignment(report.PolicyPublished.ADKIM))
	fmt.Printf("SPF Align:     %s\n", formatDMARCAlignment(report.PolicyPublished.ASPF))
	fmt.Printf("Percentage:    %d%%\n", report.PolicyPublished.Percentage)
	fmt.Println()

	// Analysis Summary
	if report.Analysis != nil {
		fmt.Println("AUTHENTICATION SUMMARY")
		fmt.Println("-" + strings.Repeat("-", 79))
		fmt.Printf("Total Emails:     %d\n", report.Analysis.TotalEmails)
		fmt.Printf("Overall Pass:     %.1f%% %s\n",
			report.Analysis.PassRate, passRateSymbol(report.Analysis.PassRate))
		fmt.Printf("SPF Pass Rate:    %.1f%% %s\n",
			report.Analysis.SPFPassRate, passRateSymbol(report.Analysis.SPFPassRate))
		fmt.Printf("DKIM Pass Rate:   %.1f%% %s\n",
			report.Analysis.DKIMPassRate, passRateSymbol(report.Analysis.DKIMPassRate))
		fmt.Println()

		// Disposition breakdown
		fmt.Println("Disposition:")
		for disp, count := range report.Analysis.DispositionStats {
			pct := 0.0
			if report.Analysis.TotalEmails > 0 {
				pct = float64(count) / float64(report.Analysis.TotalEmails) * 100
			}
			fmt.Printf("  %-12s %6d (%.1f%%)\n", disp+":", count, pct)
		}
		fmt.Println()

		// Top source countries
		if len(report.Analysis.TopSourceCountries) > 0 {
			fmt.Println("TOP SOURCE COUNTRIES")
			fmt.Println("-" + strings.Repeat("-", 79))
			limit := min(5, len(report.Analysis.TopSourceCountries))
			for i := 0; i < limit; i++ {
				cs := report.Analysis.TopSourceCountries[i]
				fmt.Printf("  %d. %s (%s): %d emails, %d failures\n",
					i+1, cs.Country, cs.CountryCode, cs.EmailCount, cs.FailCount)
			}
			fmt.Println()
		}

		// Top ASNs
		if len(report.Analysis.TopASNs) > 0 {
			fmt.Println("TOP SOURCE ORGANIZATIONS")
			fmt.Println("-" + strings.Repeat("-", 79))
			limit := min(5, len(report.Analysis.TopASNs))
			for i := 0; i < limit; i++ {
				asn := report.Analysis.TopASNs[i]
				fmt.Printf("  %d. %s (AS%d): %d emails, %d failures\n",
					i+1, asn.Organization, asn.ASN, asn.EmailCount, asn.FailCount)
			}
			fmt.Println()
		}

		// Failing sources
		if len(report.Analysis.FailingSources) > 0 {
			fmt.Println("FAILING SOURCES")
			fmt.Println("-" + strings.Repeat("-", 79))
			limit := min(10, len(report.Analysis.FailingSources))
			for i := 0; i < limit; i++ {
				fs := report.Analysis.FailingSources[i]
				location := ""
				if fs.Country != "" {
					location = fmt.Sprintf(" (%s)", fs.Country)
				}
				org := ""
				if fs.Organization != "" {
					org = fmt.Sprintf(" - %s", fs.Organization)
				}
				fmt.Printf("  %s%s%s: %d failures - %s\n",
					fs.IP, location, org, fs.FailCount, fs.FailReason)
			}
			fmt.Println()
		}

		// Recommendations
		if len(report.Analysis.Recommendations) > 0 {
			fmt.Println("RECOMMENDATIONS")
			fmt.Println("-" + strings.Repeat("-", 79))
			for _, rec := range report.Analysis.Recommendations {
				fmt.Printf("  [%s] %s\n", strings.ToUpper(rec.Priority), rec.Title)
				fmt.Printf("         %s\n", rec.Description)
				fmt.Printf("         Action: %s\n", rec.Action)
				fmt.Println()
			}
		}

		// Threat assessment
		fmt.Println("THREAT ASSESSMENT")
		fmt.Println("-" + strings.Repeat("-", 79))
		fmt.Printf("Overall Threat Level: %s %s\n",
			strings.ToUpper(report.Analysis.OverallThreatLevel),
			threatSymbol(report.Analysis.OverallThreatLevel))
	}

	// Verbose: show all records
	if verbose {
		fmt.Println()
		fmt.Println("DETAILED RECORDS")
		fmt.Println("-" + strings.Repeat("-", 79))
		for i, record := range report.Records {
			fmt.Printf("\nRecord #%d:\n", i+1)
			fmt.Printf("  Source IP:    %s\n", record.Row.SourceIP)
			fmt.Printf("  Count:        %d\n", record.Row.Count)
			fmt.Printf("  SPF:          %s\n", formatResult(record.Row.PolicyEvaluated.SPF))
			fmt.Printf("  DKIM:         %s\n", formatResult(record.Row.PolicyEvaluated.DKIM))
			fmt.Printf("  Disposition:  %s\n", record.Row.PolicyEvaluated.Disposition)
			fmt.Printf("  Header From:  %s\n", record.Identifiers.HeaderFrom)
			if record.Enrichment != nil {
				if record.Enrichment.Country != "" {
					fmt.Printf("  Location:     %s, %s\n", record.Enrichment.City, record.Enrichment.Country)
				}
				if record.Enrichment.Organization != "" {
					fmt.Printf("  Organization: %s (AS%d)\n", record.Enrichment.Organization, record.Enrichment.ASN)
				}
				fmt.Printf("  Threat Score: %.0f (%s)\n", record.Enrichment.ThreatScore, record.Enrichment.ThreatLevel)
			}
		}
	}

	fmt.Println()
	fmt.Println("=" + strings.Repeat("=", 79))
}

// outputDMARCMarkdown outputs the DMARC report in Markdown format
func outputDMARCMarkdown(report *DMARCAggregateReport, verbose bool) {
	fmt.Println("# DMARC Aggregate Report Analysis")
	fmt.Println()

	// Metadata
	fmt.Println("## Report Information")
	fmt.Println()
	fmt.Println("| Field | Value |")
	fmt.Println("|-------|-------|")
	fmt.Printf("| Organization | %s |\n", escapeMarkdown(report.Metadata.OrgName))
	fmt.Printf("| Report ID | `%s` |\n", report.Metadata.ReportID)
	fmt.Printf("| Email | %s |\n", report.Metadata.Email)
	fmt.Printf("| Period | %s to %s |\n",
		formatUnixTime(report.Metadata.DateRange.Begin),
		formatUnixTime(report.Metadata.DateRange.End))
	fmt.Println()

	// Policy
	fmt.Println("## Domain Policy")
	fmt.Println()
	fmt.Printf("- **Domain**: %s\n", report.PolicyPublished.Domain)
	fmt.Printf("- **Policy**: `%s`\n", report.PolicyPublished.Policy)
	fmt.Printf("- **Subdomain Policy**: `%s`\n", report.PolicyPublished.SubdomainPolicy)
	fmt.Printf("- **DKIM Alignment**: %s\n", alignmentDescription(report.PolicyPublished.ADKIM))
	fmt.Printf("- **SPF Alignment**: %s\n", alignmentDescription(report.PolicyPublished.ASPF))
	fmt.Printf("- **Percentage**: %d%%\n", report.PolicyPublished.Percentage)
	fmt.Println()

	if report.Analysis != nil {
		// Summary table
		fmt.Println("## Authentication Summary")
		fmt.Println()
		fmt.Println("| Metric | Value | Status |")
		fmt.Println("|--------|-------|--------|")
		fmt.Printf("| Total Emails | %d | - |\n", report.Analysis.TotalEmails)
		fmt.Printf("| Overall Pass Rate | %.1f%% | %s |\n",
			report.Analysis.PassRate, markdownStatus(report.Analysis.PassRate))
		fmt.Printf("| SPF Pass Rate | %.1f%% | %s |\n",
			report.Analysis.SPFPassRate, markdownStatus(report.Analysis.SPFPassRate))
		fmt.Printf("| DKIM Pass Rate | %.1f%% | %s |\n",
			report.Analysis.DKIMPassRate, markdownStatus(report.Analysis.DKIMPassRate))
		fmt.Println()

		// Disposition
		fmt.Println("### Disposition Breakdown")
		fmt.Println()
		fmt.Println("| Disposition | Count | Percentage |")
		fmt.Println("|-------------|-------|------------|")
		for disp, count := range report.Analysis.DispositionStats {
			pct := 0.0
			if report.Analysis.TotalEmails > 0 {
				pct = float64(count) / float64(report.Analysis.TotalEmails) * 100
			}
			fmt.Printf("| %s | %d | %.1f%% |\n", disp, count, pct)
		}
		fmt.Println()

		// Top countries table
		if len(report.Analysis.TopSourceCountries) > 0 {
			fmt.Println("## Top Source Countries")
			fmt.Println()
			fmt.Println("| Country | Code | Emails | Failures |")
			fmt.Println("|---------|------|--------|----------|")
			limit := min(10, len(report.Analysis.TopSourceCountries))
			for i := 0; i < limit; i++ {
				cs := report.Analysis.TopSourceCountries[i]
				fmt.Printf("| %s | %s | %d | %d |\n",
					escapeMarkdown(cs.Country), cs.CountryCode, cs.EmailCount, cs.FailCount)
			}
			fmt.Println()
		}

		// Failing sources
		if len(report.Analysis.FailingSources) > 0 {
			fmt.Println("## Failing Sources")
			fmt.Println()
			fmt.Println("| IP Address | Country | Organization | Failures | Reason |")
			fmt.Println("|------------|---------|--------------|----------|--------|")
			limit := min(10, len(report.Analysis.FailingSources))
			for i := 0; i < limit; i++ {
				fs := report.Analysis.FailingSources[i]
				fmt.Printf("| %s | %s | %s | %d | %s |\n",
					fs.IP, fs.Country, escapeMarkdown(fs.Organization), fs.FailCount, fs.FailReason)
			}
			fmt.Println()
		}

		// Recommendations
		if len(report.Analysis.Recommendations) > 0 {
			fmt.Println("## Recommendations")
			fmt.Println()
			for _, rec := range report.Analysis.Recommendations {
				fmt.Printf("### %s %s\n", priorityEmoji(rec.Priority), rec.Title)
				fmt.Println()
				fmt.Printf("%s\n", rec.Description)
				fmt.Println()
				fmt.Printf("**Action**: %s\n", rec.Action)
				fmt.Println()
			}
		}

		// Threat assessment
		fmt.Println("## Threat Assessment")
		fmt.Println()
		fmt.Printf("**Overall Threat Level**: %s %s\n",
			strings.ToUpper(report.Analysis.OverallThreatLevel),
			threatEmoji(report.Analysis.OverallThreatLevel))
	}

	// Verbose: all records as table
	if verbose && len(report.Records) > 0 {
		fmt.Println()
		fmt.Println("## Detailed Records")
		fmt.Println()
		fmt.Println("| # | Source IP | Count | SPF | DKIM | Disposition | Header From |")
		fmt.Println("|---|-----------|-------|-----|------|-------------|-------------|")
		for i, record := range report.Records {
			fmt.Printf("| %d | %s | %d | %s | %s | %s | %s |\n",
				i+1,
				record.Row.SourceIP,
				record.Row.Count,
				record.Row.PolicyEvaluated.SPF,
				record.Row.PolicyEvaluated.DKIM,
				record.Row.PolicyEvaluated.Disposition,
				record.Identifiers.HeaderFrom)
		}
	}
}

// Helper functions for DMARC output

func formatUnixTime(timestamp int64) string {
	return time.Unix(timestamp, 0).UTC().Format("2006-01-02 15:04 UTC")
}

func formatDMARCPolicy(policy string) string {
	switch strings.ToLower(policy) {
	case "none":
		return "none (monitor only)"
	case "quarantine":
		return "quarantine (mark as suspicious)"
	case "reject":
		return "reject (block delivery)"
	default:
		return policy
	}
}

func formatDMARCAlignment(align string) string {
	switch strings.ToLower(align) {
	case "r":
		return "relaxed"
	case "s":
		return "strict"
	default:
		return align
	}
}

func passRateSymbol(rate float64) string {
	if rate >= 95 {
		return "✓"
	} else if rate >= 80 {
		return "⚠"
	}
	return "✗"
}

func threatSymbol(level string) string {
	switch strings.ToLower(level) {
	case "low":
		return "✓"
	case "medium":
		return "⚠"
	case "high":
		return "✗"
	case "critical":
		return "✗✗"
	default:
		return ""
	}
}

func escapeMarkdown(s string) string {
	// Escape pipe characters for markdown tables
	return strings.ReplaceAll(s, "|", "\\|")
}

func alignmentDescription(align string) string {
	switch strings.ToLower(align) {
	case "r":
		return "Relaxed (organizational domain match)"
	case "s":
		return "Strict (exact domain match)"
	default:
		return align
	}
}

func markdownStatus(rate float64) string {
	if rate >= 95 {
		return "Good"
	} else if rate >= 80 {
		return "Warning"
	}
	return "Critical"
}

func priorityEmoji(priority string) string {
	switch strings.ToLower(priority) {
	case "high":
		return "[HIGH]"
	case "medium":
		return "[MEDIUM]"
	case "low":
		return "[LOW]"
	default:
		return ""
	}
}

func threatEmoji(level string) string {
	switch strings.ToLower(level) {
	case "low":
		return "(Good)"
	case "medium":
		return "(Warning)"
	case "high":
		return "(Elevated Risk)"
	case "critical":
		return "(CRITICAL)"
	default:
		return ""
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

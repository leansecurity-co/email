package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	_ "github.com/emersion/go-message/charset"
	"github.com/rotisserie/eris"
	"github.com/yeka/zip"
)

// Security configuration constants
const (
	MaxFileSizeBytes     = 50 * 1024 * 1024   // 50MB limit
	MaxHeaderLength      = 10000              // Maximum header field length
	MaxZipFiles          = 100                // Maximum files in ZIP archive
	MaxUncompressedSize  = 100 * 1024 * 1024  // 100MB uncompressed limit
	MaxCompressionRatio  = 100                // 100:1 compression ratio limit
	MaxHeaderSearchBytes = 10000              // Limit for binary header search
	MaxRegexMatches      = 50                 // Limit regex matches to prevent ReDoS
)

// EmailSecurityReport contains the analysis results of email security headers
type EmailSecurityReport struct {
	From              string              `json:"from"`
	To                string              `json:"to"`
	Subject           string              `json:"subject"`
	Date              string              `json:"date"`
	MessageID         string              `json:"message_id"`
	SPFResults        []SPFResult         `json:"spf_results"`
	DKIMResults       []DKIMResult        `json:"dkim_results"`
	DMARCResults      []DMARCResult       `json:"dmarc_results"`
	AuthResults       []AuthResult        `json:"auth_results"`
	ARCResults        []ARCResult         `json:"arc_results"`
	ReceivedSPF       string              `json:"received_spf"`
	RawHeaders        map[string][]string `json:"raw_headers,omitempty"`
}

// SPFResult represents SPF authentication result
type SPFResult struct {
	Result      string `json:"result"`       // pass, fail, softfail, neutral, none, temperror, permerror
	Domain      string `json:"domain"`
	Explanation string `json:"explanation"`
	ClientIP    string `json:"client_ip,omitempty"`
}

// DKIMResult represents DKIM signature validation result
type DKIMResult struct {
	Result    string `json:"result"`    // pass, fail, neutral, temperror, permerror, none
	Domain    string `json:"domain"`
	Selector  string `json:"selector"`
	Signature string `json:"signature,omitempty"`
	HeaderD   string `json:"header_d,omitempty"` // d= parameter
	HeaderS   string `json:"header_s,omitempty"` // s= parameter
	HeaderA   string `json:"header_a,omitempty"` // a= algorithm
}

// DMARCResult represents DMARC policy evaluation result
type DMARCResult struct {
	Result          string `json:"result"`           // pass, fail, none
	Policy          string `json:"policy"`           // none, quarantine, reject
	Disposition     string `json:"disposition"`      // none, quarantine, reject
	SPFAlignment    string `json:"spf_alignment"`    // pass, fail
	DKIMAlignment   string `json:"dkim_alignment"`   // pass, fail
	Domain          string `json:"domain"`
	SubdomainPolicy string `json:"subdomain_policy,omitempty"`
}

// AuthResult represents parsed Authentication-Results header
type AuthResult struct {
	AuthServID string         `json:"authserv_id"`
	Version    int            `json:"version,omitempty"`
	Methods    []AuthMethod   `json:"methods"`
}

// AuthMethod represents individual authentication method result
type AuthMethod struct {
	Method     string            `json:"method"`      // spf, dkim, dmarc, arc
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

func main() {
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
	defer f.Close()

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
					defer rc.Close()
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
		fmt.Sscanf(match[1], "%d", &result.Instance)
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

	fmt.Printf("SPF Authentication:   %s\n", formatBool(spfPass))
	fmt.Printf("DKIM Authentication:  %s\n", formatBool(dkimPass))
	fmt.Printf("DMARC Authentication: %s\n", formatBool(dmarcPass))
	fmt.Println()

	// Overall assessment
	if spfPass && dkimPass && dmarcPass {
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

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

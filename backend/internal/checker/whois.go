package checker

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

type WHOISResult struct {
	IsSuccess    bool
	ExpiresAt    time.Time
	ErrorMessage string
}

func queryWHOIS(server, query string) (string, error) {
	conn, err := net.DialTimeout("tcp", server+":43", 10*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to connect to %s: %w", server, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	_, err = conn.Write([]byte(query + "\r\n"))
	if err != nil {
		return "", fmt.Errorf("failed to send query: %w", err)
	}

	var response strings.Builder
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		response.WriteString(scanner.Text())
		response.WriteString("\n")
	}

	return response.String(), nil
}

func findReferralServer(tld string) (string, error) {
	response, err := queryWHOIS("whois.iana.org", tld)
	if err != nil {
		return "", err
	}

	re := regexp.MustCompile(`(?im)^whois:\s*(\S+)`)
	match := re.FindStringSubmatch(response)
	if match == nil {
		return "", fmt.Errorf("no referral server found for TLD .%s", tld)
	}

	return match[1], nil
}

func extractExpiryDate(response string) (time.Time, error) {
	fieldNames := []string{
		"Registry Expiry Date",
		"Registrar Registration Expiration Date",
		"Expiry Date",
		"Expiration Date",
		"paid-till",
	}

	dateLayouts := []string{
		time.RFC3339,          
		"2006-01-02T15:04:05Z", 
		"2006-01-02",           
		"02-Jan-2006",          
	}

	for _, field := range fieldNames {
		re := regexp.MustCompile(`(?i)` + field + `:\s*(.+)`)
		match := re.FindStringSubmatch(response)
		if match == nil {
			continue
		}

		rawValue := strings.TrimSpace(match[1])
		for _, layout := range dateLayouts {
			if parsed, err := time.Parse(layout, rawValue); err == nil {
				return parsed, nil
			}
		}
	}

	return time.Time{}, fmt.Errorf("no recognizable expiry date field found")
}

func CheckWHOIS(hostname string) WHOISResult {
	parts := strings.Split(hostname, ".")
	if len(parts) < 2 {
		return WHOISResult{IsSuccess: false, ErrorMessage: "invalid hostname"}
	}
	tld := parts[len(parts)-1]

	referralServer, err := findReferralServer(tld)
	if err != nil {
		return WHOISResult{IsSuccess: false, ErrorMessage: err.Error()}
	}

	response, err := queryWHOIS(referralServer, hostname)
	if err != nil {
		return WHOISResult{IsSuccess: false, ErrorMessage: err.Error()}
	}

	expiresAt, err := extractExpiryDate(response)
	if err != nil {
		return WHOISResult{IsSuccess: false, ErrorMessage: err.Error()}
	}

	return WHOISResult{IsSuccess: true, ExpiresAt: expiresAt}
}
package checker

import (
	"fmt"
	"testing"
)

func TestDebugIANAResponse(t *testing.T) {
	response, err := queryWHOIS("whois.iana.org", "com")
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	fmt.Println("=== RAW IANA RESPONSE ===")
	fmt.Println(response)
	fmt.Println("=== END ===")
}
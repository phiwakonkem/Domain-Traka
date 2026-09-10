package checker

import (
	"testing"
	"time"
)

func TestCheckWHOIS_RealDomain(t *testing.T) {
	result := CheckWHOIS("google.com")

	if !result.IsSuccess {
		t.Errorf("expected google.com WHOIS lookup to succeed, got error=%s", result.ErrorMessage)
	}

	if result.ExpiresAt.Before(time.Now()) {
		t.Error("expected domain expiry to be in the future")
	}
}
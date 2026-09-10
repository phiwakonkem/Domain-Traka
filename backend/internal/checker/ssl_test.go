package checker

import (
	"testing"
	"time"
)

func TestCheckSSL_RealDomain(t *testing.T) {
	result := CheckSSL("google.com")

	if !result.IsSuccess {
		t.Errorf("expected google.com to have a valid SSL cert, got error=%s", result.ErrorMessage)
	}

	if result.ExpiresAt.Before(time.Now()) {
		t.Error("expected certificate expiry to be in the future")
	}
}

func TestCheckSSL_NonexistentDomain(t *testing.T) {
	result := CheckSSL("this-domain-definitely-does-not-exist-12345.com")

	if result.IsSuccess {
		t.Error("expected a nonexistent domain to fail SSL check")
	}
}
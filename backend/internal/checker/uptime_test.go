package checker

import "testing"

func TestCheckUptime_RealDomain(t *testing.T) {
	result := CheckUptime("google.com")

	if !result.IsSuccess {
		t.Errorf("expected google.com to be up, got IsSuccess=false, error=%s", result.ErrorMessage)
	}

	if result.StatusCode == 0 {
		t.Error("expected a non-zero status code")
	}

	if result.ResponseTimeMs <= 0 {
		t.Error("expected a positive response time")
	}
}

func TestCheckUptime_NonexistentDomain(t *testing.T) {
	result := CheckUptime("this-domain-definitely-does-not-exist-12345.com")

	if result.IsSuccess {
		t.Error("expected a nonexistent domain to fail, got IsSuccess=true")
	}

	if result.ErrorMessage == "" {
		t.Error("expected an error message explaining the failure")
	}
}
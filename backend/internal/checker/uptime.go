package checker

import (
	"net/http"
	"time"
)

type UptimeResult struct {
	IsSuccess      bool
	StatusCode     int
	ResponseTimeMs int
	ErrorMessage   string
}

func CheckUptime(hostname string) UptimeResult {
	client := http.Client{
		Timeout: 10 * time.Second, 
	}

	url := "https://" + hostname
	start := time.Now()

	resp, err := client.Get(url)
	elapsed := time.Since(start)

	if err != nil {
		return UptimeResult{
			IsSuccess:    false,
			ErrorMessage: err.Error(),
		}
	}
	defer resp.Body.Close()

	isSuccess := resp.StatusCode < 400

	return UptimeResult{
		IsSuccess:      isSuccess,
		StatusCode:     resp.StatusCode,
		ResponseTimeMs: int(elapsed.Milliseconds()),
	}
}
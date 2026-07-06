package discover

import (
	"net/http"
	"time"
)

const searchHTTPTimeout = 60 * time.Second

const searchUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

// newDirectHTTPClient — client HTTP direct (legacy).
func newDirectHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   searchHTTPTimeout,
		Transport: &http.Transport{},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

package detector

import (
	"net/http"
	"testing"
)

func TestDetectXSS_DirectReflection(t *testing.T) {
	payload := `<script>alert(1)</script>`
	body := `<html>` + payload + `</html>`
	result := DetectXSS(body, payload)
	if !result.Found {
		t.Fatal("expected XSS detection")
	}
}

func TestDetectXSS_NoReflection(t *testing.T) {
	result := DetectXSS("<html>safe</html>", `<script>alert(1)</script>`)
	if result.Found {
		t.Fatal("expected no detection")
	}
}

func TestDetectOpenRedirect_LocationHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Location", "https://evil.com/phish")
	result := DetectOpenRedirect(302, headers, "", "https://evil.com")
	if !result.Found {
		t.Fatal("expected redirect detection")
	}
}

func TestDetectLFI_Passwd(t *testing.T) {
	body := "root:x:0:0:root:/root:/bin/bash"
	result := DetectLFI(body)
	if !result.Found {
		t.Fatal("expected LFI detection")
	}
}

func TestDetectSSRF_Metadata(t *testing.T) {
	body := `{"ami-id": "ami-12345", "instance-id": "i-abc"}`
	result := DetectSSRF(body, "http://169.254.169.254")
	if !result.Found {
		t.Fatal("expected SSRF detection")
	}
}

package scanner

import (
	"context"
	"testing"

	"github.com/sqli-hunter/sqli-hunter/internal/benchserver"
	"github.com/sqli-hunter/sqli-hunter/internal/client"
	"github.com/sqli-hunter/sqli-hunter/internal/models"
	"github.com/sqli-hunter/sqli-hunter/internal/payloads"
)

func TestScanner_RealWorld_EcommerceMySQL(t *testing.T) {
	srv := benchserver.New()
	defer srv.Close()

	target := models.ScanTarget{
		URL: srv.URL + "/shop/product.php?id=42", Method: "GET",
		Params: map[string]string{"id": "42"},
	}
	result := scan(t, target)
	assertVuln(t, result, models.SQLiError)
}

func TestScanner_RealWorld_LoginPOST(t *testing.T) {
	srv := benchserver.New()
	defer srv.Close()

	target := models.ScanTarget{
		URL: srv.URL + "/auth/login", Method: "POST",
		Data: map[string]string{"username": "admin", "password": "test"},
	}
	result := scan(t, target)
	assertVuln(t, result, models.SQLiError)
}

func TestScanner_RealWorld_PostgreSQL_API(t *testing.T) {
	srv := benchserver.New()
	defer srv.Close()

	target := models.ScanTarget{
		URL: srv.URL + "/api/v2/users?user_id=100", Method: "GET",
		Params: map[string]string{"user_id": "100"},
	}
	result := scan(t, target)
	assertVuln(t, result, models.SQLiError)
}

func TestScanner_RealWorld_MongoNoSQL(t *testing.T) {
	srv := benchserver.New()
	defer srv.Close()

	target := models.ScanTarget{
		URL: srv.URL + "/api/v1/auth?email=user@test.com", Method: "GET",
		Params: map[string]string{"email": "user@test.com"},
	}
	result := scan(t, target)
	assertVuln(t, result, models.NoSQL)
}

func TestScanner_RealWorld_OracleHealthcare(t *testing.T) {
	srv := benchserver.New()
	defer srv.Close()

	target := models.ScanTarget{
		URL: srv.URL + "/portal/patient?patient_id=P001", Method: "GET",
		Params: map[string]string{"patient_id": "P001"},
	}
	result := scan(t, target)
	assertVuln(t, result, models.SQLiError)
}

func TestScanner_RealWorld_BankingUnion(t *testing.T) {
	srv := benchserver.New()
	defer srv.Close()

	target := models.ScanTarget{
		URL: srv.URL + "/banking/statement?account=ACC-001", Method: "GET",
		Params: map[string]string{"account": "ACC-001"},
	}
	result := scan(t, target)
	assertVuln(t, result, models.SQLiUnion)
}

func TestScanner_RealWorld_SafeNoDetection(t *testing.T) {
	srv := benchserver.New()
	defer srv.Close()

	targets := []models.ScanTarget{
		{URL: srv.URL + "/static/about?lang=fr", Method: "GET", Params: map[string]string{"lang": "fr"}},
		{URL: srv.URL + "/safe/users?id=1", Method: "GET", Params: map[string]string{"id": "1"}},
	}
	for _, target := range targets {
		result := scan(t, target)
		if len(result.Findings) > 0 {
			t.Fatalf("faux positif sur %s: %d findings", target.URL, len(result.Findings))
		}
	}
}

func scan(t *testing.T, target models.ScanTarget) models.ScanResult {
	t.Helper()
	opts := models.ScanOptions{
		Mode: models.ScanFast, Categories: payloads.DefaultCategories(models.ScanFast),
		TimeoutSec: 5, Threads: 4, RateLimitMs: 0, EarlyExit: false,
	}
	sc := New(client.New(5, nil, nil), opts, nil, nil)
	return sc.Scan(context.Background(), target)
}

func assertVuln(t *testing.T, result models.ScanResult, expected models.VulnType) {
	t.Helper()
	for _, f := range result.Findings {
		if f.VulnType == expected {
			return
		}
	}
	types := make([]string, 0, len(result.Findings))
	for _, f := range result.Findings {
		types = append(types, string(f.VulnType))
	}
	t.Fatalf("expected %s, got findings: %v (tested %d payloads)", expected, types, result.TestedPayloads)
}

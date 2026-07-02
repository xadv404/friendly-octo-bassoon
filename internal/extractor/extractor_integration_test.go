package extractor

import (
	"context"
	"strings"
	"testing"

	"github.com/sqli-hunter/sqli-hunter/internal/benchserver"
	"github.com/sqli-hunter/sqli-hunter/internal/client"
	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

func TestExtractFromFinding_MySQL(t *testing.T) {
	srv := benchserver.New()
	defer srv.Close()

	target := models.ScanTarget{
		URL: srv.URL + "/extract/mysql?id=1", Method: "GET",
		Params: map[string]string{"id": "1"},
	}
	finding := models.Finding{
		URL: target.URL, Parameter: "id",
		VulnType: models.SQLiError, DBMS: "mysql", Confidence: models.Confirmed,
	}

	ext := New(client.New(5, nil, nil), nil, nil, nil, true)
	data := ext.ExtractFromFinding(context.Background(), target, finding)

	if len(data) == 0 {
		t.Fatal("expected extractions")
	}

	foundPII := false
	for _, d := range data {
		if d.DataType == models.DataPII {
			foundPII = true
			if !strings.Contains(d.Value, "@") {
				t.Fatalf("missing email in PII:\n%s", d.Value)
			}
			if strings.Contains(d.Value, "email:") || strings.Contains(d.Value, "nom:") || strings.Contains(d.Value, "telephone:") {
				t.Fatalf("should only extract email address:\n%s", d.Value)
			}
		}
	}
	if !foundPII {
		t.Fatalf("expected PII extraction, got %d items", len(data))
	}
}

func TestExtractDirect_NoSQL(t *testing.T) {
	srv := benchserver.New()
	defer srv.Close()

	target := models.ScanTarget{
		URL: srv.URL + "/extract/nosql?user=guest", Method: "GET",
		Params: map[string]string{"user": "guest"},
	}

	ext := New(client.New(5, nil, nil), nil, nil, nil, true)
	result := ext.ExtractDirect(context.Background(), target)

	if len(result.Extractions) == 0 {
		t.Fatal("expected nosql extraction")
	}
}

func TestExtractAll_AfterScan(t *testing.T) {
	srv := benchserver.New()
	defer srv.Close()

	target := models.ScanTarget{
		URL: srv.URL + "/extract/mysql?id=1", Method: "GET",
		Params: map[string]string{"id": "1"},
	}
	findings := []models.Finding{{
		URL: target.URL, Parameter: "id",
		VulnType: models.SQLiError, DBMS: "mysql",
	}}

	ext := New(client.New(5, nil, nil), nil, nil, nil, true)
	result := ext.ExtractAll(context.Background(), target, findings)

	if len(result.Extractions) == 0 {
		t.Fatal("expected extractions from union finding")
	}
}

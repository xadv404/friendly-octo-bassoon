package extractor

import (
	"context"
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

	ext := New(client.New(5, nil, nil), nil, nil, nil)
	data := ext.ExtractFromFinding(context.Background(), target, finding)

	if len(data) == 0 {
		t.Fatal("expected extractions")
	}

	foundVersion := false
	for _, d := range data {
		if d.DataType == models.DataVersion {
			foundVersion = true
		}
	}
	if !foundVersion {
		t.Fatalf("expected version extraction, got %d items", len(data))
	}
}

func TestExtractDirect_NoSQL(t *testing.T) {
	srv := benchserver.New()
	defer srv.Close()

	target := models.ScanTarget{
		URL: srv.URL + "/extract/nosql?user=guest", Method: "GET",
		Params: map[string]string{"user": "guest"},
	}

	ext := New(client.New(5, nil, nil), nil, nil, nil)
	result := ext.ExtractDirect(context.Background(), target)

	if len(result.Extractions) == 0 {
		t.Fatal("expected nosql extraction")
	}
}

func TestExtractAll_AfterScan(t *testing.T) {
	srv := benchserver.New()
	defer srv.Close()

	target := models.ScanTarget{
		URL: srv.URL + "/shop/search?q=1", Method: "GET",
		Params: map[string]string{"q": "1"},
	}
	findings := []models.Finding{{
		URL: target.URL, Parameter: "q",
		VulnType: models.SQLiUnion, DBMS: "mysql",
	}}

	ext := New(client.New(5, nil, nil), nil, nil, nil)
	result := ext.ExtractAll(context.Background(), target, findings)

	if len(result.Extractions) == 0 {
		t.Fatal("expected extractions from union finding")
	}
}

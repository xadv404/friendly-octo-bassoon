package extractor

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/sqli-hunter/sqli-hunter/internal/benchserver"
	"github.com/sqli-hunter/sqli-hunter/internal/client"
	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

func TestPoolExtractsOnDedicatedWorkers(t *testing.T) {
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

	var count atomic.Int32
	ext := New(client.New(5, nil, nil),
		func(models.ExtractedData) { count.Add(1) },
		nil, nil, true,
	)

	pool := NewPool(ext, 2)
	pool.Start(context.Background())

	for i := 0; i < 3; i++ {
		pool.Submit(target, finding)
	}
	pool.CloseAndWait()

	if count.Load() == 0 {
		t.Fatal("expected extractions via pool workers")
	}
}

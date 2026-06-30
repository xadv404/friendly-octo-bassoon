package benchmark

import (
	"context"
	"fmt"
	"strings"

	"github.com/sqli-hunter/sqli-hunter/internal/benchserver"
	"github.com/sqli-hunter/sqli-hunter/internal/client"
	"github.com/sqli-hunter/sqli-hunter/internal/models"
	"github.com/sqli-hunter/sqli-hunter/internal/payloads"
	"github.com/sqli-hunter/sqli-hunter/internal/scanner"
)

// Result représente le résultat d'un benchmark.
type Result struct {
	Total    int
	Passed   int
	Failed   []string
	Findings int
}

// Run exécute le benchmark complet contre le serveur local.
func Run() (Result, error) {
	srv := benchserver.New()
	defer srv.Close()

	opts := models.ScanOptions{
		Mode:       models.ScanFast,
		Categories: payloads.DefaultCategories(models.ScanFast),
		TimeoutSec: 5,
		Threads:    4,
		RateLimitMs: 0,
		EarlyExit:  false, // tester toutes les vulns en benchmark
	}

	httpClient := client.New(opts.TimeoutSec, nil, nil)
	sc := scanner.New(httpClient, opts, nil, nil)

	out := Result{}
	targets := srv.Targets()
	out.Total = len(targets)

	for _, t := range targets {
		target := models.ScanTarget{
			URL:    t.URL,
			Method: "GET",
			Params: map[string]string{t.Param: extractParamValue(t.URL, t.Param)},
		}

		result := sc.Scan(context.Background(), target)
		found := false
		for _, f := range result.Findings {
			if string(f.VulnType) == t.Expected {
				found = true
				out.Findings++
				break
			}
		}
		if found {
			out.Passed++
		} else {
			types := make([]string, 0, len(result.Findings))
			for _, f := range result.Findings {
				types = append(types, string(f.VulnType))
			}
			out.Failed = append(out.Failed, fmt.Sprintf("%s: attendu %s, trouvé [%s]", t.Name, t.Expected, strings.Join(types, ", ")))
		}
	}

	return out, nil
}

func extractParamValue(rawURL, param string) string {
	idx := strings.Index(rawURL, param+"=")
	if idx < 0 {
		return "1"
	}
	val := rawURL[idx+len(param)+1:]
	if amp := strings.Index(val, "&"); amp >= 0 {
		val = val[:amp]
	}
	if val == "" {
		return "1"
	}
	return val
}

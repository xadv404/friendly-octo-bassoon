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

// Result représente le résultat complet du benchmark.
type Result struct {
	Total       int
	Passed      int
	Failed      []string
	FalsePos    []string
	Findings    int
	ByContext   map[string]ContextResult
	Scenarios   []ScenarioResult
}

// ContextResult résultat par contexte applicatif.
type ContextResult struct {
	Total  int
	Passed int
}

// ScenarioResult détail par scénario.
type ScenarioResult struct {
	Name      string
	Context   string
	DBMS      string
	Expected  string
	Detected  string
	Passed    bool
	RealWorld string
}

// Run exécute le benchmark complet.
func Run() (Result, error) {
	srv := benchserver.New()
	defer srv.Close()
	return RunAgainst(srv)
}

// RunAgainst exécute le benchmark sur un serveur donné.
func RunAgainst(srv *benchserver.Server) (Result, error) {
	opts := models.ScanOptions{
		Mode:        models.ScanFast,
		Categories:  payloads.DefaultCategories(models.ScanFast),
		TimeoutSec:  5,
		Threads:     8,
		RateLimitMs: 0,
		EarlyExit:   false,
	}

	httpClient := client.New(opts.TimeoutSec, nil, nil)
	sc := scanner.New(httpClient, opts, nil, nil)

	out := Result{
		ByContext: make(map[string]ContextResult),
	}

	// ── Scénarios vulnérables ──
	for _, t := range srv.VulnTargets() {
		out.Total++
		target := buildScanTarget(srv.URL, t)
		result := sc.Scan(context.Background(), target)

		sr := ScenarioResult{
			Name: t.Name, Context: string(t.Context), DBMS: t.DBMS,
			Expected: t.Expected, RealWorld: t.RealWorld,
		}

		for _, f := range result.Findings {
			if string(f.VulnType) == t.Expected {
				sr.Detected = string(f.VulnType)
				sr.Passed = true
				out.Findings++
				break
			}
		}
		if !sr.Passed && len(result.Findings) > 0 {
			sr.Detected = string(result.Findings[0].VulnType)
		}

		out.Scenarios = append(out.Scenarios, sr)

		ctxKey := string(t.Context)
		cr := out.ByContext[ctxKey]
		cr.Total++
		if sr.Passed {
			out.Passed++
			cr.Passed++
		} else {
			types := detectedTypes(result.Findings)
			out.Failed = append(out.Failed,
				fmt.Sprintf("[%s] %s: attendu %s, trouvé [%s]", t.Context, t.Name, t.Expected, strings.Join(types, ", ")))
		}
		out.ByContext[ctxKey] = cr
	}

	// ── Scénarios safe (pas de faux positifs) ──
	for _, t := range srv.SafeTargets() {
		target := buildScanTarget(srv.URL, t)
		result := sc.Scan(context.Background(), target)
		if len(result.Findings) > 0 {
			types := detectedTypes(result.Findings)
			out.FalsePos = append(out.FalsePos,
				fmt.Sprintf("[%s] %s: faux positif [%s]", t.Context, t.Name, strings.Join(types, ", ")))
		}
	}

	return out, nil
}

func buildScanTarget(baseURL string, t benchserver.Target) models.ScanTarget {
	target := models.ScanTarget{
		URL:    strings.Replace(t.URL, baseURL, t.URL, 1),
		Method: t.Method,
		Params: make(map[string]string),
		Data:   make(map[string]string),
	}

	// Reconstruire URL relative au serveur
	if !strings.HasPrefix(t.URL, "http") {
		target.URL = baseURL + strings.TrimPrefix(t.URL, baseURL)
	}
	target.URL = t.URL

	if t.Method == "GET" || t.Method == "" {
		if t.Param != "" {
			target.Params[t.Param] = extractParamValue(t.URL, t.Param)
		}
	}

	if len(t.Data) > 0 {
		target.Data = t.Data
	}
	if t.JSONBody != nil {
		target.JSONBody = t.JSONBody
	}

	return target
}

func detectedTypes(findings []models.Finding) []string {
	types := make([]string, 0, len(findings))
	for _, f := range findings {
		types = append(types, string(f.VulnType))
	}
	return types
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

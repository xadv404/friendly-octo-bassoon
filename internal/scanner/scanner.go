package scanner

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sqli-hunter/sqli-hunter/internal/client"
	"github.com/sqli-hunter/sqli-hunter/internal/detector"
	"github.com/sqli-hunter/sqli-hunter/internal/models"
	"github.com/sqli-hunter/sqli-hunter/internal/payloads"
)

// Scanner orchestre les tests d'injection base de données.
type Scanner struct {
	httpClient *client.HTTPClient
	opts       models.ScanOptions
	onFinding  func(models.Finding)
	onProgress func(string)
}

// New crée un scanner.
func New(httpClient *client.HTTPClient, opts models.ScanOptions, onFinding func(models.Finding), onProgress func(string)) *Scanner {
	return &Scanner{
		httpClient: httpClient,
		opts:       opts,
		onFinding:  onFinding,
		onProgress: onProgress,
	}
}

// Scan lance le scan sur la cible.
func (s *Scanner) Scan(ctx context.Context, target models.ScanTarget) models.ScanResult {
	result := models.ScanResult{Target: target}

	paramNames := s.collectParams(target)
	if len(paramNames) == 0 {
		result.Errors = append(result.Errors, "aucun paramètre à tester")
		return result
	}
	result.TestedParams = len(paramNames)

	jobs := payloads.BuildJobs(s.opts)

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, s.opts.Threads))

	for _, param := range paramNames {
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()

			baseline := s.getBaseline(ctx, target, p)
			foundCategories := make(map[models.VulnCategory]bool)

			for _, job := range jobs {
				if ctx.Err() != nil {
					return
				}
				if s.opts.EarlyExit && foundCategories[job.Category] {
					continue
				}

				s.rateLimit()
				finding, tested := s.runJob(ctx, target, p, job, baseline)
				mu.Lock()
				result.TestedPayloads += tested
				if finding != nil {
					result.Findings = append(result.Findings, *finding)
					if s.onFinding != nil {
						s.onFinding(*finding)
					}
					if s.opts.EarlyExit && (finding.Confidence == models.Confirmed || finding.Confidence == models.High) {
						foundCategories[job.Category] = true
					}
				}
				mu.Unlock()
			}
		}(param)
	}

	wg.Wait()
	return result
}

func (s *Scanner) runJob(ctx context.Context, target models.ScanTarget, param string, job models.TestJob, baseline baselineResp) (*models.Finding, int) {
	switch job.VulnType {
	case models.SQLiError:
		return s.testError(ctx, target, param, job.Payload, baseline)
	case models.SQLiUnion:
		return s.testUnion(ctx, target, param, job.Payload, baseline)
	case models.SQLiBoolean:
		return s.testBoolean(ctx, target, param, job.Payload, job.PayloadB, baseline)
	case models.SQLiTime:
		return s.testTime(ctx, target, param, job.Payload, baseline)
	case models.NoSQL:
		return s.testNoSQL(ctx, target, param, job.Payload, baseline)
	default:
		return nil, 0
	}
}

type baselineResp struct {
	body string
	code int
	ms   float64
	err  error
}

func (s *Scanner) getBaseline(ctx context.Context, target models.ScanTarget, param string) baselineResp {
	original := s.getOriginalValue(target, param)
	resp, err := s.httpClient.Send(ctx, target, param, original)
	if err != nil {
		return baselineResp{err: err}
	}
	return baselineResp{
		body: resp.Body,
		code: resp.StatusCode,
		ms:   float64(resp.Duration.Milliseconds()),
	}
}

func (s *Scanner) testError(ctx context.Context, target models.ScanTarget, param, payload string, baseline baselineResp) (*models.Finding, int) {
	s.progress(fmt.Sprintf("[%s] sqli:error → %s", param, truncate(payload, 50)))
	resp, err := s.httpClient.Send(ctx, target, param, payload)
	if err != nil {
		return nil, 1
	}

	sqlErr := detector.DetectSQLError(resp.Body)
	if sqlErr.Found {
		confidence := models.High
		if sqlErr.DBMS != "generic" {
			confidence = models.Confirmed
		}
		return &models.Finding{
			URL: resp.URL, Parameter: param, Payload: payload,
			VulnType: models.SQLiError, Confidence: confidence,
			Evidence: "erreur SQL — accès DB probable: " + sqlErr.Snippet,
			DBMS: sqlErr.DBMS,
			ResponseTimeMs: float64(resp.Duration.Milliseconds()), StatusCode: resp.StatusCode,
		}, 1
	}

	if baseline.err == nil {
		if leak, desc := detector.DetectDBLeak(resp.Body, baseline.body); leak {
			return &models.Finding{
				URL: resp.URL, Parameter: param, Payload: payload,
				VulnType: models.SQLiError, Confidence: models.High,
				Evidence: desc,
				ResponseTimeMs: float64(resp.Duration.Milliseconds()), StatusCode: resp.StatusCode,
			}, 1
		}
	}

	return nil, 1
}

func (s *Scanner) testUnion(ctx context.Context, target models.ScanTarget, param, payload string, baseline baselineResp) (*models.Finding, int) {
	s.progress(fmt.Sprintf("[%s] sqli:union → %s", param, truncate(payload, 50)))
	resp, err := s.httpClient.Send(ctx, target, param, payload)
	if err != nil {
		return nil, 1
	}

	sqlErr := detector.DetectSQLError(resp.Body)
	if sqlErr.Found {
		return &models.Finding{
			URL: resp.URL, Parameter: param, Payload: payload,
			VulnType: models.SQLiUnion, Confidence: models.High,
			Evidence: "erreur SQL UNION — accès DB: " + sqlErr.Snippet, DBMS: sqlErr.DBMS,
			ResponseTimeMs: float64(resp.Duration.Milliseconds()), StatusCode: resp.StatusCode,
		}, 1
	}

	if baseline.err == nil && detector.DetectUnionSuccess(resp.Body, baseline.body) {
		return &models.Finding{
			URL: resp.URL, Parameter: param, Payload: payload,
			VulnType: models.SQLiUnion, Confidence: models.Confirmed,
			Evidence: "données DB extraites via UNION (version/schéma)",
			ResponseTimeMs: float64(resp.Duration.Milliseconds()), StatusCode: resp.StatusCode,
		}, 1
	}

	return nil, 1
}

func (s *Scanner) testBoolean(ctx context.Context, target models.ScanTarget, param, trueP, falseP string, baseline baselineResp) (*models.Finding, int) {
	s.progress(fmt.Sprintf("[%s] sqli:boolean → %s", param, truncate(trueP, 30)))
	trueResp, errT := s.httpClient.Send(ctx, target, param, trueP)
	if errT != nil {
		return nil, 2
	}
	falseResp, errF := s.httpClient.Send(ctx, target, param, falseP)
	if errF != nil {
		return nil, 2
	}
	differs, evidence := detector.ResponsesDiffer(
		trueResp.Body, falseResp.Body, baseline.body,
		trueResp.StatusCode, falseResp.StatusCode, baseline.code,
	)
	if !differs {
		return nil, 2
	}
	return &models.Finding{
		URL: trueResp.URL, Parameter: param, Payload: trueP + " | " + falseP,
		VulnType: models.SQLiBoolean, Confidence: models.Medium,
		Evidence: "injection boolean — requêtes DB manipulables: " + evidence,
		ResponseTimeMs: float64(trueResp.Duration.Milliseconds()), StatusCode: trueResp.StatusCode,
	}, 2
}

func (s *Scanner) testTime(ctx context.Context, target models.ScanTarget, param, payload string, baseline baselineResp) (*models.Finding, int) {
	s.progress(fmt.Sprintf("[%s] sqli:time → %s", param, truncate(payload, 50)))
	threshold := s.opts.TimeThresholdMs
	if threshold == 0 {
		threshold = float64(s.opts.TimeDelaySec) * 1000 * 0.8
	}
	resp, err := s.httpClient.Send(ctx, target, param, payload)
	if err != nil {
		return nil, 1
	}
	ms := float64(resp.Duration.Milliseconds())
	baseMs := baseline.ms
	if baseMs == 0 {
		baseMs = 500
	}
	delayMs := float64(s.opts.TimeDelaySec) * 1000
	if ms >= delayMs*0.75 && ms > baseMs+threshold {
		confidence := models.Medium
		if ms >= delayMs*0.9 {
			confidence = models.High
		}
		return &models.Finding{
			URL: resp.URL, Parameter: param, Payload: payload,
			VulnType: models.SQLiTime, Confidence: confidence,
			Evidence: fmt.Sprintf("time-based — requête DB exécutée (%.0fms)", ms),
			ResponseTimeMs: ms, StatusCode: resp.StatusCode,
		}, 1
	}
	return nil, 1
}

func (s *Scanner) testNoSQL(ctx context.Context, target models.ScanTarget, param, payload string, baseline baselineResp) (*models.Finding, int) {
	s.progress(fmt.Sprintf("[%s] nosql → %s", param, truncate(payload, 50)))
	resp, err := s.httpClient.Send(ctx, target, param, payload)
	if err != nil {
		return nil, 1
	}
	baseBody := ""
	if baseline.err == nil {
		baseBody = baseline.body
	}
	nosql := detector.DetectNoSQL(resp.Body, baseBody, payload)
	if !nosql.Found {
		return nil, 1
	}
	return &models.Finding{
		URL: resp.URL, Parameter: param, Payload: payload,
		VulnType: models.NoSQL, Confidence: models.High,
		Evidence: nosql.Evidence + ": " + nosql.Snippet,
		DBMS: "nosql",
		ResponseTimeMs: float64(resp.Duration.Milliseconds()), StatusCode: resp.StatusCode,
	}, 1
}

func (s *Scanner) collectParams(target models.ScanTarget) []string {
	seen := make(map[string]bool)
	var names []string
	for k := range target.Params {
		if !seen[k] {
			seen[k] = true
			names = append(names, k)
		}
	}
	for k := range target.Data {
		if !seen[k] {
			seen[k] = true
			names = append(names, k)
		}
	}
	if target.JSONBody != nil {
		for k := range flattenJSONKeys(target.JSONBody, "") {
			if !seen[k] {
				seen[k] = true
				names = append(names, k)
			}
		}
	}
	return names
}

func (s *Scanner) getOriginalValue(target models.ScanTarget, param string) string {
	if v, ok := target.Params[param]; ok {
		return v
	}
	if v, ok := target.Data[param]; ok {
		return v
	}
	if target.JSONBody != nil {
		if v, ok := getNestedValue(target.JSONBody, param); ok {
			return fmt.Sprintf("%v", v)
		}
	}
	return "1"
}

func (s *Scanner) rateLimit() {
	if s.opts.RateLimitMs > 0 {
		time.Sleep(time.Duration(s.opts.RateLimitMs) * time.Millisecond)
	}
}

func (s *Scanner) progress(msg string) {
	if s.opts.Verbose && s.onProgress != nil {
		s.onProgress(msg)
	}
}

func flattenJSONKeys(m map[string]any, prefix string) map[string]bool {
	keys := make(map[string]bool)
	for k, v := range m {
		full := k
		if prefix != "" {
			full = prefix + "." + k
		}
		keys[full] = true
		if sub, ok := v.(map[string]any); ok {
			for sk := range flattenJSONKeys(sub, full) {
				keys[sk] = true
			}
		}
	}
	return keys
}

func getNestedValue(m map[string]any, key string) (any, bool) {
	if !strings.Contains(key, ".") {
		v, ok := m[key]
		return v, ok
	}
	parts := strings.SplitN(key, ".", 2)
	sub, ok := m[parts[0]].(map[string]any)
	if !ok {
		return nil, false
	}
	return getNestedValue(sub, parts[1])
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

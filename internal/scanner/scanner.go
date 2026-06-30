package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sqli-hunter/sqli-hunter/internal/client"
	"github.com/sqli-hunter/sqli-hunter/internal/detector"
	"github.com/sqli-hunter/sqli-hunter/internal/models"
	"github.com/sqli-hunter/sqli-hunter/internal/payloads"
)

// Scanner orchestre les tests de vulnérabilités.
type Scanner struct {
	httpClient  *client.HTTPClient
	noRedirect  *client.HTTPClient
	opts        models.ScanOptions
	onFinding   func(models.Finding)
	onProgress  func(string)
}

// New crée un scanner.
func New(httpClient *client.HTTPClient, opts models.ScanOptions, onFinding func(models.Finding), onProgress func(string)) *Scanner {
	return &Scanner{
		httpClient: httpClient,
		noRedirect: httpClient.WithoutRedirects(),
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
		return s.testError(ctx, target, param, job.Payload)
	case models.SQLiUnion:
		return s.testUnion(ctx, target, param, job.Payload, baseline)
	case models.SQLiBoolean:
		return s.testBoolean(ctx, target, param, job.Payload, job.PayloadB, baseline)
	case models.SQLiTime:
		return s.testTime(ctx, target, param, job.Payload, baseline)
	case models.XSS:
		return s.testXSS(ctx, target, param, job.Payload)
	case models.OpenRedirect:
		return s.testRedirect(ctx, target, param, job.Payload)
	case models.LFI:
		return s.testLFI(ctx, target, param, job.Payload)
	case models.SSRF:
		return s.testSSRF(ctx, target, param, job.Payload)
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

func (s *Scanner) testError(ctx context.Context, target models.ScanTarget, param, payload string) (*models.Finding, int) {
	s.progress(fmt.Sprintf("[%s] sqli:error → %s", param, truncate(payload, 50)))
	resp, err := s.httpClient.Send(ctx, target, param, payload)
	if err != nil {
		return nil, 1
	}
	sqlErr := detector.DetectSQLError(resp.Body)
	if !sqlErr.Found {
		return nil, 1
	}
	confidence := models.High
	if sqlErr.DBMS != "generic" {
		confidence = models.Confirmed
	}
	return &models.Finding{
		URL: resp.URL, Parameter: param, Payload: payload,
		VulnType: models.SQLiError, Confidence: confidence,
		Evidence: sqlErr.Snippet, DBMS: sqlErr.DBMS,
		ResponseTimeMs: float64(resp.Duration.Milliseconds()), StatusCode: resp.StatusCode,
	}, 1
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
			Evidence: "erreur SQL UNION: " + sqlErr.Snippet, DBMS: sqlErr.DBMS,
			ResponseTimeMs: float64(resp.Duration.Milliseconds()), StatusCode: resp.StatusCode,
		}, 1
	}
	if baseline.err == nil && detector.DetectUnionSuccess(resp.Body, baseline.body) {
		return &models.Finding{
			URL: resp.URL, Parameter: param, Payload: payload,
			VulnType: models.SQLiUnion, Confidence: models.Medium,
			Evidence: "données DBMS dans réponse UNION",
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
		VulnType: models.SQLiBoolean, Confidence: models.Medium, Evidence: evidence,
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
			Evidence: fmt.Sprintf("délai %.0fms (baseline: %.0fms)", ms, baseMs),
			ResponseTimeMs: ms, StatusCode: resp.StatusCode,
		}, 1
	}
	return nil, 1
}

func (s *Scanner) testXSS(ctx context.Context, target models.ScanTarget, param, payload string) (*models.Finding, int) {
	s.progress(fmt.Sprintf("[%s] xss → %s", param, truncate(payload, 50)))
	resp, err := s.httpClient.Send(ctx, target, param, payload)
	if err != nil {
		return nil, 1
	}
	xss := detector.DetectXSS(resp.Body, payload)
	if !xss.Found {
		return nil, 1
	}
	return &models.Finding{
		URL: resp.URL, Parameter: param, Payload: payload,
		VulnType: models.XSS, Confidence: models.High,
		Evidence: xss.Context + ": " + xss.Snippet,
		ResponseTimeMs: float64(resp.Duration.Milliseconds()), StatusCode: resp.StatusCode,
	}, 1
}

func (s *Scanner) testRedirect(ctx context.Context, target models.ScanTarget, param, payload string) (*models.Finding, int) {
	s.progress(fmt.Sprintf("[%s] redirect → %s", param, truncate(payload, 50)))
	resp, err := s.noRedirect.Send(ctx, target, param, payload)
	if err != nil {
		return nil, 1
	}
	redir := detector.DetectOpenRedirect(resp.StatusCode, resp.Headers, resp.Body, payload)
	if !redir.Found {
		return nil, 1
	}
	return &models.Finding{
		URL: resp.URL, Parameter: param, Payload: payload,
		VulnType: models.OpenRedirect, Confidence: models.High,
		Evidence: redir.Evidence,
		ResponseTimeMs: float64(resp.Duration.Milliseconds()), StatusCode: resp.StatusCode,
	}, 1
}

func (s *Scanner) testLFI(ctx context.Context, target models.ScanTarget, param, payload string) (*models.Finding, int) {
	s.progress(fmt.Sprintf("[%s] lfi → %s", param, truncate(payload, 50)))
	resp, err := s.httpClient.Send(ctx, target, param, payload)
	if err != nil {
		return nil, 1
	}
	lfi := detector.DetectLFI(resp.Body)
	if !lfi.Found {
		return nil, 1
	}
	return &models.Finding{
		URL: resp.URL, Parameter: param, Payload: payload,
		VulnType: models.LFI, Confidence: models.Confirmed,
		Evidence: lfi.Evidence + ": " + lfi.Snippet,
		ResponseTimeMs: float64(resp.Duration.Milliseconds()), StatusCode: resp.StatusCode,
	}, 1
}

func (s *Scanner) testSSRF(ctx context.Context, target models.ScanTarget, param, payload string) (*models.Finding, int) {
	s.progress(fmt.Sprintf("[%s] ssrf → %s", param, truncate(payload, 50)))
	resp, err := s.httpClient.Send(ctx, target, param, payload)
	if err != nil {
		return nil, 1
	}
	ssrf := detector.DetectSSRF(resp.Body, payload)
	if !ssrf.Found {
		return nil, 1
	}
	return &models.Finding{
		URL: resp.URL, Parameter: param, Payload: payload,
		VulnType: models.SSRF, Confidence: models.Medium,
		Evidence: ssrf.Evidence + ": " + ssrf.Snippet,
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
	if !containsDot(key) {
		v, ok := m[key]
		return v, ok
	}
	parts := splitFirst(key, ".")
	sub, ok := m[parts[0]].(map[string]any)
	if !ok {
		return nil, false
	}
	return getNestedValue(sub, parts[1])
}

func containsDot(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return true
		}
	}
	return false
}

func splitFirst(s, sep string) [2]string {
	for i := 0; i < len(s); i++ {
		if s[i] == sep[0] {
			return [2]string{s[:i], s[i+1:]}
		}
	}
	return [2]string{s, ""}
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

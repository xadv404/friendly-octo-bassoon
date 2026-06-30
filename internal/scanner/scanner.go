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

// Scanner orchestre les tests SQL injection.
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

// Scan lance le scan complet sur la cible.
func (s *Scanner) Scan(ctx context.Context, target models.ScanTarget) models.ScanResult {
	result := models.ScanResult{Target: target}

	paramNames := s.collectParams(target)
	if len(paramNames) == 0 {
		result.Errors = append(result.Errors, "aucun paramètre à tester")
		return result
	}

	result.TestedParams = len(paramNames)

	// Baseline pour comparaison boolean/union
	baseline := s.getBaseline(ctx, target, paramNames[0])
	if baseline.err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("baseline: %v", baseline.err))
	}

	techniques := s.opts.Techniques
	if len(techniques) == 0 {
		techniques = payloads.AllTechniques()
	}

	payloadSets := payloads.GetPayloads(techniques, s.opts.IncludeWAF, s.opts.CustomPayloads)
	booleanPairs := payloads.GetBooleanPairs()
	timePayloads := payloads.FormatTimePayloads(s.opts.TimeDelaySec)

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, s.opts.Threads))

	for _, param := range paramNames {
		for technique, plist := range payloadSets {
			switch technique {
			case models.BooleanBlind:
				for _, pair := range booleanPairs {
					if ctx.Err() != nil {
						break
					}
					wg.Add(1)
					sem <- struct{}{}
					go func(p string, bp payloads.BooleanPair) {
						defer wg.Done()
						defer func() { <-sem }()
						s.rateLimit()
						finding, tested := s.testBoolean(ctx, target, p, bp, baseline)
						mu.Lock()
						result.TestedPayloads += tested
						if finding != nil {
							result.Findings = append(result.Findings, *finding)
							if s.onFinding != nil {
								s.onFinding(*finding)
							}
						}
						mu.Unlock()
					}(param, pair)
				}
			case models.TimeBlind:
				for _, payload := range timePayloads {
					if ctx.Err() != nil {
						break
					}
					wg.Add(1)
					sem <- struct{}{}
					go func(p, pl string) {
						defer wg.Done()
						defer func() { <-sem }()
						s.rateLimit()
						finding, tested := s.testTime(ctx, target, p, pl, baseline)
						mu.Lock()
						result.TestedPayloads += tested
						if finding != nil {
							result.Findings = append(result.Findings, *finding)
							if s.onFinding != nil {
								s.onFinding(*finding)
							}
						}
						mu.Unlock()
					}(param, payload)
				}
			default:
				for _, payload := range plist {
					if ctx.Err() != nil {
						break
					}
					wg.Add(1)
					sem <- struct{}{}
					go func(p, pl string, tech models.InjectionType) {
						defer wg.Done()
						defer func() { <-sem }()
						s.rateLimit()
						var finding *models.Finding
						var tested int
						switch tech {
						case models.ErrorBased:
							finding, tested = s.testError(ctx, target, p, pl)
						case models.UnionBased:
							finding, tested = s.testUnion(ctx, target, p, pl, baseline)
						}
						mu.Lock()
						result.TestedPayloads += tested
						if finding != nil {
							result.Findings = append(result.Findings, *finding)
							if s.onFinding != nil {
								s.onFinding(*finding)
							}
						}
						mu.Unlock()
					}(param, payload, technique)
				}
			}
		}
	}

	wg.Wait()
	return result
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
	s.progress(fmt.Sprintf("[%s] error-based → %s", param, truncate(payload, 50)))

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
		URL:            resp.URL,
		Parameter:      param,
		Payload:        payload,
		InjectionType:  models.ErrorBased,
		Confidence:     confidence,
		Evidence:       sqlErr.Snippet,
		DBMS:           sqlErr.DBMS,
		ResponseTimeMs: float64(resp.Duration.Milliseconds()),
		StatusCode:     resp.StatusCode,
	}, 1
}

func (s *Scanner) testUnion(ctx context.Context, target models.ScanTarget, param, payload string, baseline baselineResp) (*models.Finding, int) {
	s.progress(fmt.Sprintf("[%s] union-based → %s", param, truncate(payload, 50)))

	resp, err := s.httpClient.Send(ctx, target, param, payload)
	if err != nil {
		return nil, 1
	}

	sqlErr := detector.DetectSQLError(resp.Body)
	if sqlErr.Found {
		return &models.Finding{
			URL:            resp.URL,
			Parameter:      param,
			Payload:        payload,
			InjectionType:  models.UnionBased,
			Confidence:     models.High,
			Evidence:       "erreur SQL lors du test UNION: " + sqlErr.Snippet,
			DBMS:           sqlErr.DBMS,
			ResponseTimeMs: float64(resp.Duration.Milliseconds()),
			StatusCode:     resp.StatusCode,
		}, 1
	}

	if baseline.err == nil && detector.DetectUnionSuccess(resp.Body, baseline.body) {
		return &models.Finding{
			URL:            resp.URL,
			Parameter:      param,
			Payload:        payload,
			InjectionType:  models.UnionBased,
			Confidence:     models.Medium,
			Evidence:       "données DBMS détectées dans la réponse UNION",
			ResponseTimeMs: float64(resp.Duration.Milliseconds()),
			StatusCode:     resp.StatusCode,
		}, 1
	}

	return nil, 1
}

func (s *Scanner) testBoolean(ctx context.Context, target models.ScanTarget, param string, pair payloads.BooleanPair, baseline baselineResp) (*models.Finding, int) {
	s.progress(fmt.Sprintf("[%s] boolean-blind → %s / %s", param, truncate(pair.True, 25), truncate(pair.False, 25)))

	trueResp, errT := s.httpClient.Send(ctx, target, param, pair.True)
	if errT != nil {
		return nil, 2
	}
	falseResp, errF := s.httpClient.Send(ctx, target, param, pair.False)
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
		URL:            trueResp.URL,
		Parameter:      param,
		Payload:        pair.True + " | " + pair.False,
		InjectionType:  models.BooleanBlind,
		Confidence:     models.Medium,
		Evidence:       evidence,
		ResponseTimeMs: float64(trueResp.Duration.Milliseconds()),
		StatusCode:     trueResp.StatusCode,
	}, 2
}

func (s *Scanner) testTime(ctx context.Context, target models.ScanTarget, param, payload string, baseline baselineResp) (*models.Finding, int) {
	s.progress(fmt.Sprintf("[%s] time-blind → %s", param, truncate(payload, 50)))

	threshold := s.opts.TimeThresholdMs
	if threshold == 0 {
		threshold = float64(s.opts.TimeDelaySec)*1000*0.8
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
			URL:            resp.URL,
			Parameter:      param,
			Payload:        payload,
			InjectionType:  models.TimeBlind,
			Confidence:     confidence,
			Evidence:       fmt.Sprintf("délai %.0fms (baseline: %.0fms, attendu: ~%.0fms)", ms, baseMs, delayMs),
			ResponseTimeMs: ms,
			StatusCode:     resp.StatusCode,
		}, 1
	}

	return nil, 1
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
		if s[i] == sep[0] && i+len(sep) <= len(s) {
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

package targets

import (
	"fmt"
	"net/url"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

// Defaults options globales appliquées à chaque URL.
type Defaults struct {
	Method  string
	Headers map[string]string
	Cookies map[string]string
	Params  map[string]string
	Data    map[string]string
	JSON    map[string]any
}

// FromURL construit une cible à partir d'une URL (params extraits de la query).
func FromURL(raw string, d Defaults) (models.ScanTarget, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return models.ScanTarget{}, fmt.Errorf("URL invalide : %w", err)
	}

	params := make(map[string]string)
	for k, vals := range u.Query() {
		if len(vals) > 0 {
			params[k] = vals[0]
		}
	}
	for k, v := range d.Params {
		params[k] = v
	}

	data := make(map[string]string)
	for k, v := range d.Data {
		data[k] = v
	}

	if len(params) == 0 && len(data) == 0 && d.JSON == nil {
		return models.ScanTarget{}, fmt.Errorf("aucun paramètre dans %s", truncate(raw, 80))
	}

	method := d.Method
	if method == "" {
		method = "GET"
	}
	if len(data) > 0 || d.JSON != nil {
		if method == "GET" {
			method = "POST"
		}
	}

	headers := copyMap(d.Headers)
	cookies := copyMap(d.Cookies)

	return models.ScanTarget{
		URL:      raw,
		Method:   method,
		Params:   params,
		Data:     data,
		Headers:  headers,
		Cookies:  cookies,
		JSONBody: d.JSON,
	}, nil
}

func copyMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

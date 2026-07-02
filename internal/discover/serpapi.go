package discover

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const serpAPIEndpoint = "https://serpapi.com/search.json"

// serpAPIResponse structure minimale de la réponse SerpAPI Google Light.
type serpAPIResponse struct {
	OrganicResults []serpAPIOrganic `json:"organic_results"`
	Error          string           `json:"error"`
}

type serpAPIOrganic struct {
	Link      string           `json:"link"`
	Sitelinks *serpAPISitelinks `json:"sitelinks"`
}

type serpAPISitelinks struct {
	Inline []struct {
		Link string `json:"link"`
	} `json:"inline"`
}

func serpAPIKey() string {
	return strings.TrimSpace(os.Getenv("SERPAPI_API_KEY"))
}

// UseSerpAPI indique si la clé SerpAPI est configurée.
func UseSerpAPI() bool {
	return serpAPIKey() != ""
}

// GoogleBackendLabel décrit le backend Google actif (CLI).
func GoogleBackendLabel() string {
	if UseOpenSerp() {
		return "google (OpenSerp API)"
	}
	if HasDiscoverProxy() {
		return "google direct + proxy BP"
	}
	return "google direct"
}

func (g *googleClient) searchSerpAPI(ctx context.Context, query string, start int) ([]string, error) {
	key := serpAPIKey()
	if key == "" {
		return nil, fmt.Errorf("serpapi: SERPAPI_API_KEY manquant")
	}

	u, err := url.Parse(serpAPIEndpoint)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("engine", "google_light")
	q.Set("api_key", key)
	q.Set("q", query)
	q.Set("start", fmt.Sprintf("%d", start))
	q.Set("num", "50")
	q.Set("hl", "fr")
	q.Set("gl", "ch")
	q.Set("google_domain", "google.ch")
	q.Set("location", "Switzerland")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: searchHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("serpapi HTTP %d: %s", resp.StatusCode, truncateErrBody(body))
	}

	var parsed serpAPIResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("serpapi JSON: %w", err)
	}
	if parsed.Error != "" {
		return nil, fmt.Errorf("serpapi: %s", parsed.Error)
	}

	return filterSwissURLs(parseSerpAPIResults(parsed)), nil
}

func parseSerpAPIResults(resp serpAPIResponse) []string {
	seen := make(map[string]struct{})
	var out []string

	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		if reGoogleSkip.MatchString(raw) {
			return
		}
		if _, ok := seen[raw]; ok {
			return
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}

	for _, item := range resp.OrganicResults {
		add(item.Link)
		if item.Sitelinks != nil {
			for _, sl := range item.Sitelinks.Inline {
				add(sl.Link)
			}
		}
	}
	return out
}

func truncateErrBody(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

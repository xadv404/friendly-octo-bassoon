package discover

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/go-rod/stealth"
)

func googleHeadlessSearch(ctx context.Context, searchURL string) (string, error) {
	proxy := ""
	if pool := getProxyPool(); pool.hasProxies() {
		proxy = pool.first().String()
	}

	l := launcher.New().
		Headless(true).
		NoSandbox(true).
		Set("disable-dev-shm-usage", "").
		Set("disable-gpu", "").
		Set("window-size", "1920,1080").
		Set("lang", "fr-CH")
	if proxy != "" {
		l = l.Proxy(proxy)
	}

	controlURL, err := l.Launch()
	if err != nil {
		return "", fmt.Errorf("google headless: %w", err)
	}

	browser := rod.New().ControlURL(controlURL)
	if err := browser.Connect(); err != nil {
		return "", fmt.Errorf("google headless connect: %w", err)
	}
	defer browser.MustClose()

	page, err := stealth.Page(browser)
	if err != nil {
		return "", fmt.Errorf("google headless page: %w", err)
	}
	defer page.MustClose()

	page = page.Timeout(45 * time.Second)
	if err := page.Navigate(googleHomeURL); err != nil {
		return "", err
	}
	if err := page.WaitLoad(); err != nil {
		return "", err
	}
	time.Sleep(600 * time.Millisecond)

	if err := page.Navigate(searchURL); err != nil {
		return "", err
	}
	if err := page.WaitLoad(); err != nil {
		return "", err
	}

	if clicked, _ := clickGoogleConsent(page); clicked {
		_ = page.WaitLoad()
		time.Sleep(800 * time.Millisecond)
	}

	html, err := page.HTML()
	if err != nil {
		return "", err
	}
	if isGoogleConsentPage(html) {
		if clicked, _ := clickGoogleConsent(page); clicked {
			_ = page.WaitLoad()
			time.Sleep(800 * time.Millisecond)
			html, err = page.HTML()
			if err != nil {
				return "", err
			}
		}
	}
	if isGoogleEnableJS(html) {
		time.Sleep(1500 * time.Millisecond)
		_ = page.WaitLoad()
		html, err = page.HTML()
		if err != nil {
			return "", err
		}
	}
	return html, nil
}

func clickGoogleConsent(page *rod.Page) (bool, error) {
	selectors := []string{
		`form[action*="consent.google"] input[type="submit"][value*="accepter"]`,
		`form[action*="consent.google"] input[aria-label*="accepter"]`,
		`button#L2AGLb`,
		`input[value="Tout accepter"]`,
	}
	for _, sel := range selectors {
		el, err := page.Timeout(3 * time.Second).Element(sel)
		if err != nil {
			continue
		}
		if err := el.Click(proto.InputMouseButtonLeft, 1); err != nil {
			continue
		}
		return true, nil
	}
	// fallback: submit accept form via JS
	ok, err := page.Eval(`() => {
		const forms = document.querySelectorAll('form[action*="consent.google"]');
		for (const f of forms) {
			const aps = f.querySelector('input[name="set_aps"][value="true"]');
			if (aps) { f.submit(); return true; }
		}
		return false;
	}`)
	if err != nil {
		return false, err
	}
	if ok.Value.Bool() {
		return true, nil
	}
	return false, nil
}

func googleHeadlessFetch(ctx context.Context, query string, start int) ([]string, error) {
	strat := googleSearchStrategies()[0]
	searchURL, err := buildGoogleSearchURL(strat, query, start)
	if err != nil {
		return nil, err
	}
	html, err := googleHeadlessSearch(ctx, searchURL)
	if err != nil {
		return nil, err
	}
	if isGoogleHardBlocked(html) || strings.Contains(html, "/sorry") {
		return nil, fmt.Errorf("google headless: blocage")
	}
	urls := filterSwissURLs(parseGoogleResults(html))
	if len(urls) == 0 {
		return nil, fmt.Errorf("google headless: page vide")
	}
	return urls, nil
}

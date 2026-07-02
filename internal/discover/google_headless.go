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
	l := launcher.New().
		Headless(true).
		NoSandbox(true).
		Set("disable-dev-shm-usage", "").
		Set("disable-gpu", "").
		Set("window-size", "1920,1080").
		Set("lang", "fr-CH")

	var proxyUser, proxyPass string
	if pool := getProxyPool(); pool.hasProxies() {
		hostPort, user, pass, ok := pool.proxyCredentials()
		if ok {
			l = l.Proxy(hostPort)
			proxyUser, proxyPass = user, pass
		}
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

	if proxyUser != "" {
		go browser.MustHandleAuth(proxyUser, proxyPass)()
	}

	page, err := stealth.Page(browser)
	if err != nil {
		return "", fmt.Errorf("google headless page: %w", err)
	}
	defer page.MustClose()

	page = page.Timeout(60 * time.Second)
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
	time.Sleep(800 * time.Millisecond)

	html, err := page.HTML()
	if err != nil {
		return "", err
	}
	if isGoogleConsentPage(html) {
		_ = submitGoogleConsent(page)
		time.Sleep(1500 * time.Millisecond)
		_ = page.WaitLoad()
		html, err = page.HTML()
		if err != nil {
			return "", err
		}
	}
	if isGoogleEnableJS(html) {
		time.Sleep(2 * time.Second)
		_ = page.WaitLoad()
		html, err = page.HTML()
		if err != nil {
			return "", err
		}
	}
	return html, nil
}

func submitGoogleConsent(page *rod.Page) error {
	selectors := []string{
		`form[action*="consent.google"] input[type="submit"][value*="accepter"]`,
		`form[action*="consent.google"] input[aria-label*="accepter"]`,
		`input[value="Tout accepter"]`,
	}
	for _, sel := range selectors {
		el, err := page.Timeout(4 * time.Second).Element(sel)
		if err != nil {
			continue
		}
		wait := page.WaitNavigation(proto.PageLifecycleEventNameNetworkAlmostIdle)
		if err := el.Click(proto.InputMouseButtonLeft, 1); err != nil {
			continue
		}
		wait()
		return nil
	}
	forms, err := page.Elements(`form[action*="consent.google"]`)
	if err != nil {
		return err
	}
	for _, form := range forms {
		if _, err := form.Element(`input[name="set_aps"][value="true"]`); err != nil {
			continue
		}
		btn, err := form.Element(`input[type="submit"]`)
		if err != nil {
			continue
		}
		wait := page.WaitNavigation(proto.PageLifecycleEventNameNetworkAlmostIdle)
		if err := btn.Click(proto.InputMouseButtonLeft, 1); err != nil {
			continue
		}
		wait()
		return nil
	}
	return fmt.Errorf("google headless: consent introuvable")
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

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

func googleHeadlessSearch(ctx context.Context, searchURL string) (string, []string, error) {
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
		return "", nil, fmt.Errorf("google headless: %w", err)
	}

	browser := rod.New().ControlURL(controlURL)
	if err := browser.Connect(); err != nil {
		return "", nil, fmt.Errorf("google headless connect: %w", err)
	}
	defer browser.MustClose()

	if proxyUser != "" {
		go browser.MustHandleAuth(proxyUser, proxyPass)()
	}

	page, err := stealth.Page(browser)
	if err != nil {
		return "", nil, fmt.Errorf("google headless page: %w", err)
	}
	defer page.MustClose()

	page = page.Timeout(60 * time.Second)
	if err := page.Navigate(googleHomeURL); err != nil {
		return "", nil, err
	}
	if err := page.WaitLoad(); err != nil {
		return "", nil, err
	}
	time.Sleep(600 * time.Millisecond)

	if err := page.Navigate(searchURL); err != nil {
		return "", nil, err
	}
	if err := page.WaitLoad(); err != nil {
		return "", nil, err
	}
	time.Sleep(800 * time.Millisecond)

	html, err := googleHeadlessPageHTML(page)
	if err != nil {
		return "", nil, err
	}
	if isGoogleConsentPage(html) {
		_ = submitGoogleConsent(page)
		time.Sleep(1500 * time.Millisecond)
		_ = page.WaitLoad()
		html, _ = googleHeadlessPageHTML(page)
	}
	time.Sleep(1 * time.Second)
	_ = page.WaitLoad()

	if info, err := page.Info(); err == nil && strings.Contains(info.URL, "/sorry") {
		html, _ := googleHeadlessPageHTML(page)
		return html, nil, fmt.Errorf("google headless: sorry")
	}

	urls := googleHeadlessExtractURLs(page)
	if len(urls) == 0 {
		html, err = googleHeadlessPageHTML(page)
		if err != nil {
			return "", nil, err
		}
		urls = parseGoogleResults(html)
	}
	return html, urls, nil
}

func googleHeadlessPageHTML(page *rod.Page) (string, error) {
	var lastErr error
	for i := 0; i < 4; i++ {
		html, err := page.HTML()
		if err == nil {
			return html, nil
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
		_ = page.WaitLoad()
	}
	return "", lastErr
}

func googleHeadlessExtractURLs(page *rod.Page) []string {
	links, err := page.Elements("a")
	if err != nil {
		return nil
	}
	var hrefs []string
	for _, link := range links {
		href, err := link.Attribute("href")
		if err != nil || href == nil || *href == "" {
			continue
		}
		hrefs = append(hrefs, *href)
	}
	if len(hrefs) == 0 {
		return nil
	}
	return parseGoogleResults(strings.Join(hrefs, "\n"))
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
	searchURL, err := buildGoogleSearchURL(googleSearchStrategy{
		baseURL: "https://www.google.ch/search",
		params:  nil, // navigateur réel : résultats JS (pas gbv)
	}, query, start)
	if err != nil {
		return nil, err
	}
	html, urls, err := googleHeadlessSearch(ctx, searchURL)
	if err != nil {
		return nil, err
	}
	if strings.Contains(html, "/sorry") || strings.Contains(html, "google.com/sorry") {
		return nil, fmt.Errorf("google headless: sorry")
	}
	if isGoogleHardBlocked(html) {
		return nil, fmt.Errorf("google headless: blocage")
	}
	urls = filterSwissURLs(urls)
	if len(urls) == 0 {
		return nil, fmt.Errorf("google headless: page vide")
	}
	return urls, nil
}

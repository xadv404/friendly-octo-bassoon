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
	_ = page.WaitLoad()
	time.Sleep(800 * time.Millisecond)

	if err := page.Navigate(searchURL); err != nil {
		return "", nil, err
	}
	_ = page.WaitLoad()

	html, urls, err := googleHeadlessWaitResults(page)
	if err != nil {
		return html, nil, err
	}
	return html, urls, nil
}

func googleHeadlessWaitResults(page *rod.Page) (string, []string, error) {
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := page.Info(); err == nil {
			if strings.Contains(info.URL, "/sorry") {
				html, _ := googleHeadlessPageHTML(page)
				return html, nil, fmt.Errorf("google headless: sorry")
			}
		}

		html, err := googleHeadlessPageHTML(page)
		if err != nil {
			time.Sleep(400 * time.Millisecond)
			continue
		}
		if isGoogleConsentPage(html) {
			_ = submitGoogleConsent(page)
			time.Sleep(1200 * time.Millisecond)
			_ = page.WaitLoad()
			continue
		}
		if urls := filterSwissURLs(googleHeadlessExtractURLs(page)); len(urls) > 0 {
			return html, urls, nil
		}
		if urls := filterSwissURLs(parseGoogleResults(html)); len(urls) > 0 {
			return html, urls, nil
		}
		if isGoogleHardBlocked(html) {
			return html, nil, fmt.Errorf("google headless: blocage")
		}
		time.Sleep(500 * time.Millisecond)
	}
	html, _ := googleHeadlessPageHTML(page)
	return html, nil, fmt.Errorf("google headless: page vide")
}

func googleHeadlessPageHTML(page *rod.Page) (string, error) {
	return page.HTML()
}

func googleHeadlessExtractURLs(page *rod.Page) []string {
	links, err := page.Elements(`a[href*="/url?q="], a[href*="uddg="], a[href^="http"]`)
	if err != nil {
		links, err = page.Elements("a")
		if err != nil {
			return nil
		}
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
	return fmt.Errorf("google headless: consent introuvable")
}

func googleHeadlessFetch(ctx context.Context, query string, start int) ([]string, error) {
	searchURL, err := buildGoogleSearchURL(googleSearchStrategy{
		baseURL: "https://www.google.ch/search",
		params:  nil,
	}, query, start)
	if err != nil {
		return nil, err
	}
	_, urls, err := googleHeadlessSearch(ctx, searchURL)
	if err != nil {
		return nil, err
	}
	if len(urls) == 0 {
		return nil, fmt.Errorf("google headless: page vide")
	}
	return urls, nil
}

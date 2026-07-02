package discover

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/go-rod/stealth"
)

func googleHeadlessFetch(ctx context.Context, query string, start, attempt int) ([]string, error) {
	modes := []func(context.Context, string, int) ([]string, error){
		googleHeadlessViaSearchBox,
		googleHeadlessViaURL,
	}
	fn := modes[attempt%len(modes)]
	urls, err := fn(ctx, query, start)
	if err != nil {
		return nil, err
	}
	if len(urls) == 0 {
		return nil, fmt.Errorf("google headless: page vide")
	}
	return urls, nil
}

func googleHeadlessViaURL(ctx context.Context, query string, start int) ([]string, error) {
	searchURL, err := buildGoogleSearchURL(googleSearchStrategy{
		baseURL: "https://www.google.ch/search",
		params:  nil,
	}, query, start)
	if err != nil {
		return nil, err
	}
	_, urls, err := googleHeadlessBrowse(ctx, func(page *rod.Page) error {
		return page.Navigate(searchURL)
	})
	return urls, err
}

func googleHeadlessViaSearchBox(ctx context.Context, query string, start int) ([]string, error) {
	_, urls, err := googleHeadlessBrowse(ctx, func(page *rod.Page) error {
		box, err := page.Timeout(8 * time.Second).Element(`textarea[name="q"], input[name="q"]`)
		if err != nil {
			return page.Navigate(mustSearchURL(query, start))
		}
		if err := box.SelectAllText(); err == nil {
			_ = box.Input("")
		}
		time.Sleep(googleJitter(200 * time.Millisecond))
		if err := box.Input(query); err != nil {
			return page.Navigate(mustSearchURL(query, start))
		}
		time.Sleep(googleJitter(300 * time.Millisecond))
		if start > 0 {
			return page.Navigate(mustSearchURL(query, start))
		}
		btn, err := page.Element(`button[type="submit"], input[name="btnK"], input[type="submit"]`)
		if err != nil {
			return page.Keyboard.Press(input.Enter)
		}
		wait := page.WaitNavigation(proto.PageLifecycleEventNameNetworkAlmostIdle)
		if err := btn.Click(proto.InputMouseButtonLeft, 1); err != nil {
			return page.Keyboard.Press(input.Enter)
		}
		wait()
		return nil
	})
	return urls, err
}

func mustSearchURL(query string, start int) string {
	u, _ := buildGoogleSearchURL(googleSearchStrategy{
		baseURL: "https://www.google.ch/search",
		params:  nil,
	}, query, start)
	return u
}

func googleHeadlessBrowse(ctx context.Context, navigate func(*rod.Page) error) (string, []string, error) {
	l := launcher.New().
		Headless(true).
		NoSandbox(true).
		Set("disable-dev-shm-usage", "").
		Set("disable-gpu", "").
		Set("window-size", "1920,1080").
		Set("lang", "fr-CH").
		Set("disable-blink-features", "AutomationControlled").
		Delete("enable-automation")

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
		return "", nil, err
	}
	defer page.MustClose()
	page = page.Timeout(70 * time.Second)

	if err := page.Navigate(googleHomeURL); err != nil {
		return "", nil, err
	}
	_ = page.WaitLoad()
	time.Sleep(googleJitter(900 * time.Millisecond))

	if err := navigate(page); err != nil {
		return "", nil, err
	}
	_ = page.WaitLoad()
	googleHeadlessHumanize(page)

	return googleHeadlessWaitResults(page)
}

func googleHeadlessHumanize(page *rod.Page) {
	_, _ = page.Eval(`() => { window.scrollBy(0, 200 + Math.random()*300); }`)
	time.Sleep(googleJitter(500 * time.Millisecond))
	_, _ = page.Eval(`() => { window.scrollBy(0, 100 + Math.random()*200); }`)
	time.Sleep(googleJitter(400 * time.Millisecond))
}

func googleHeadlessWaitResults(page *rod.Page) (string, []string, error) {
	deadline := time.Now().Add(35 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := page.Info(); err == nil && strings.Contains(info.URL, "/sorry") {
			html, _ := page.HTML()
			return html, nil, fmt.Errorf("google headless: sorry")
		}

		html, err := page.HTML()
		if err != nil {
			time.Sleep(400 * time.Millisecond)
			continue
		}
		if isGoogleConsentPage(html) {
			_ = submitGoogleConsent(page)
			time.Sleep(googleJitter(1200 * time.Millisecond))
			_ = page.WaitLoad()
			googleHeadlessHumanize(page)
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
		time.Sleep(googleJitter(500 * time.Millisecond))
	}
	html, _ := page.HTML()
	return html, nil, fmt.Errorf("google headless: timeout")
}

func googleHeadlessExtractURLs(page *rod.Page) []string {
	links, err := page.Elements(`a[href*="/url?q="], a[data-ved][href^="http"], a[href^="http"]`)
	if err != nil {
		links, _ = page.Elements("a")
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
		`button#L2AGLb`,
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

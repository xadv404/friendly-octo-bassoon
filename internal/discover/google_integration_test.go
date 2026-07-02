//go:build integration

package discover

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestGoogleHeadlessLive(t *testing.T) {
	if os.Getenv("DISCOVER_PROXY") == "" {
		t.Skip("DISCOVER_PROXY non configuré")
	}
	ReloadProxyPool()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	for i := 0; i < 5; i++ {
		urls, err := googleHeadlessFetch(ctx, "site:.ch inurl:php?id=", 0, i)
		t.Logf("headless %d: urls=%d err=%v", i+1, len(urls), err)
		if len(urls) > 0 {
			t.Log(urls[0])
			return
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatal("headless failed")
}

package extractor

import "testing"

func TestScrapeEmailsFromBody(t *testing.T) {
	recs := scanEmailsInBody(`contact: hans.meier@bluewin.ch and marie@sunrise.ch`)
	if len(recs) != 2 {
		t.Fatalf("got %d emails", len(recs))
	}
	if recs[0].Email != "hans.meier@bluewin.ch" {
		t.Fatalf("unexpected %q", recs[0].Email)
	}
}

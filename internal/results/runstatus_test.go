package results

import (
	"path/filepath"
	"testing"
)

func TestRunStatusRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st := RunStatus{
		Phase:       "fresh-pass",
		DorkIndex:   10,
		DorkTotal:   53,
		URLsKept:    5,
		URLsFetched: 20,
	}
	if err := WriteRunStatus(dir, st); err != nil {
		t.Fatal(err)
	}
	got, ok := LoadRunStatus(dir)
	if !ok {
		t.Fatal("expected status file")
	}
	if got.Phase != st.Phase || got.DorkIndex != 10 || got.URLsKept != 5 {
		t.Fatalf("got %+v", got)
	}
	if _, err := filepath.Abs(dir); err != nil {
		t.Fatal(err)
	}
}

func TestCountLines(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.txt")
	if err := WriteRunStatus(dir, RunStatus{Phase: "x"}); err != nil {
		t.Fatal(err)
	}
	_ = p
	if CountLines(filepath.Join(dir, "missing.txt")) != 0 {
		t.Fatal("missing should be 0")
	}
}

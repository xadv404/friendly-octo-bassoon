package extractor

import (
	"testing"
)

func TestParseResponse_EXTRACTVALUE(t *testing.T) {
	body := "XPATH syntax error: '~8.0.32-MySQL~'"
	val, ok := ParseResponse(body, `EXTRACTVALUE`, "error", DataVersion)
	if !ok || val != "8.0.32-MySQL" {
		t.Fatalf("expected version, got %q ok=%v", val, ok)
	}
}

func TestParseResponse_Database(t *testing.T) {
	body := "XPATH syntax error: '~shop_production~'"
	val, ok := ParseResponse(body, `database()`, "error", DataDatabase)
	if !ok || val != "shop_production" {
		t.Fatalf("expected database name, got %q", val)
	}
}

func TestParseResponse_UnionVersion(t *testing.T) {
	body := "Search results: 8.0.32-MySQL Community Server"
	val, ok := ParseResponse(body, `' UNION SELECT @@version,NULL--`, "union", DataVersion)
	if !ok {
		t.Fatal("expected union version extraction")
	}
	if val == "" {
		t.Fatal("empty value")
	}
}

func TestParseResponse_NoSQLDump(t *testing.T) {
	body := `{"users":[{"username":"admin","email":"admin@corp.com"}]}`
	val, ok := ParseResponse(body, `{"$gt":""}`, "nosql", DataDump)
	if !ok || !contains(val, "admin") {
		t.Fatalf("expected dump, got %q", val)
	}
}

func TestBuildJobs_MySQL(t *testing.T) {
	jobs := BuildJobs("mysql", "sqli_error")
	if len(jobs) == 0 {
		t.Fatal("expected jobs")
	}
	hasVersion := false
	for _, j := range jobs {
		if j.DataType == DataVersion {
			hasVersion = true
		}
	}
	if !hasVersion {
		t.Fatal("expected version extraction job")
	}
}

func TestBuildUnionSelect(t *testing.T) {
	got := buildUnionSelect("@@version", 3)
	want := "@@version,NULL,NULL"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

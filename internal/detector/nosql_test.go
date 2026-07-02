package detector

import (
	"strings"
	"testing"
)

func TestDetectNoSQL_RealWorldCases(t *testing.T) {
	cases := []struct {
		name     string
		baseline string
		body     string
		payload  string
	}{
		{
			name:     "juice shop login bypass",
			baseline: `{"error":"invalid credentials"}`,
			body:     `{"token":"eyJ","user":{"email":"admin@corp.com","role":"admin"}}`,
			payload:  `{"$gt":""}`,
		},
		{
			name:     "password reset dump",
			baseline: `{"message":"email not found"}`,
			body:     `{"users":[{"email":"admin@corp.com"},{"email":"user@test.com"}]}`,
			payload:  `{"$ne":null}`,
		},
		{
			name:     "mongo error $where",
			baseline: "",
			body:     "MongoError: $where is not allowed in this context",
			payload:  `{"$where":"1==1"}`,
		},
		{
			name:     "tenant regex dump",
			baseline: `{"tenants":[]}`,
			body:     `{"tenants":[{"name":"Acme Corp","plan":"enterprise"}]}`,
			payload:  `{"$regex":".*"}`,
		},
		{
			name:     "large response dump",
			baseline: `{"error":"not found"}`,
			body:     `{"orders":[{"id":"1"},{"id":"2"},{"id":"3"}]}` + string(make([]byte, 200)),
			payload:  `{"$gt":""}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := DetectNoSQL(tc.body, tc.baseline, tc.payload)
			if !r.Found {
				t.Fatalf("expected detection for %s", tc.name)
			}
		})
	}
}

func TestDetectNoSQL_NoDetection(t *testing.T) {
	body := `{"error":"invalid credentials"}`
	r := DetectNoSQL(body, body, "normaluser")
	if r.Found {
		t.Fatal("expected no detection")
	}
}

func TestDetectNoSQL_RejectsSQLError(t *testing.T) {
	body := `You have an error in your SQL syntax near '{"$gt":""}' at line 1`
	baseline := `Product: 1`
	r := DetectNoSQL(body, baseline, `{"$gt":""}`)
	if r.Found {
		t.Fatal("expected no nosql detection on SQL error response")
	}
}

func TestDetectNoSQL_RejectsHTMLLongResponse(t *testing.T) {
	baseline := `Product: 1`
	body := `You have an error in your SQL syntax near ''' at line 1 — extra padding ` + strings.Repeat("x", 200)
	r := DetectNoSQL(body, baseline, `{"$gt":""}`)
	if r.Found {
		t.Fatal("expected no nosql on long non-JSON response")
	}
}

func TestDetectNoSQL_CouchbaseError(t *testing.T) {
	body := "Couchbase error: invalid JSON operator"
	r := DetectNoSQL(body, "", `{"$gt":""}`)
	if !r.Found {
		t.Fatal("expected couchbase/mongo error detection")
	}
}

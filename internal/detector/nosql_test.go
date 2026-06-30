package detector

import "testing"

func TestDetectNoSQL_Bypass(t *testing.T) {
	baseline := `{"error":"invalid credentials"}`
	body := `{"users":[{"username":"admin","password":"hash","email":"admin@db.local"}]}`
	result := DetectNoSQL(body, baseline, `{"$gt":""}`)
	if !result.Found {
		t.Fatal("expected NoSQL detection")
	}
}

func TestDetectNoSQL_Error(t *testing.T) {
	body := "MongoError: $where is not allowed in this context"
	result := DetectNoSQL(body, "", `{"$where":"1==1"}`)
	if !result.Found {
		t.Fatal("expected MongoDB error detection")
	}
}

func TestDetectDBLeak_Version(t *testing.T) {
	body := "Result: 8.0.32-MySQL Community Server"
	baseline := "Product id=1"
	leak, desc := DetectDBLeak(body, baseline)
	if !leak {
		t.Fatal("expected DB leak detection")
	}
	if desc == "" {
		t.Fatal("expected description")
	}
}

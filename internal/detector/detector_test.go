package detector

import "testing"

func TestDetectSQLError_MySQL(t *testing.T) {
	body := `Error: You have an error in your SQL syntax near '1'' at line 1`
	result := DetectSQLError(body)
	if !result.Found {
		t.Fatal("expected SQL error detection")
	}
	if result.DBMS != "mysql" {
		t.Errorf("expected mysql, got %s", result.DBMS)
	}
}

func TestDetectSQLError_PostgreSQL(t *testing.T) {
	body := `ERROR: syntax error at or near "'"`
	result := DetectSQLError(body)
	if !result.Found {
		t.Fatal("expected SQL error detection")
	}
	if result.DBMS != "postgresql" {
		t.Errorf("expected postgresql, got %s", result.DBMS)
	}
}

func TestDetectSQLError_NoError(t *testing.T) {
	body := `<html><body>Hello World</body></html>`
	result := DetectSQLError(body)
	if result.Found {
		t.Fatal("expected no detection")
	}
}

func TestResponsesDiffer(t *testing.T) {
	baseline := "Welcome admin, you have 10 messages"
	trueBody := "Welcome admin, you have 10 messages"
	falseBody := "Access denied"

	differs, evidence := ResponsesDiffer(trueBody, falseBody, baseline, 200, 403, 200)
	if !differs {
		t.Fatal("expected difference detection")
	}
	if evidence == "" {
		t.Fatal("expected evidence")
	}
}

func TestResponsesDiffer_Same(t *testing.T) {
	body := "same content here"
	differs, _ := ResponsesDiffer(body, body, body, 200, 200, 200)
	if differs {
		t.Fatal("expected no difference")
	}
}

func TestDetectUnionSuccess(t *testing.T) {
	baseline := `<html>search results</html>`
	body := `<html>5.7.33-MySQL</html>`
	if !DetectUnionSuccess(body, baseline) {
		t.Fatal("expected union success detection")
	}
}

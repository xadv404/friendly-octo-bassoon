package detector

import "testing"

// ── MySQL ──

func TestDetectSQLError_MySQL(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"syntax error", `Error: You have an error in your SQL syntax near '1'' at line 1`},
		{"unknown column", `Unknown column 'password' in 'field list'`},
		{"mysqli", `Warning: mysqli_fetch_array() expects parameter 1 to be mysqli_result`},
		{"acunetix test site", `Error: You have an error in your SQL syntax check the manual that corresponds to your MySQL server version`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := DetectSQLError(tc.body)
			if !r.Found || r.DBMS != "mysql" {
				t.Fatalf("expected mysql, got %+v", r)
			}
		})
	}
}

// ── PostgreSQL ──

func TestDetectSQLError_PostgreSQL(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"syntax near", `ERROR:  syntax error at or near "'"`},
		{"unterminated", `ERROR:  unterminated quoted string at or near "'"`},
		{"pg driver", `org.postgresql.util.PSQLException: ERROR: syntax error`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := DetectSQLError(tc.body)
			if !r.Found || r.DBMS != "postgresql" {
				t.Fatalf("expected postgresql, got %+v", r)
			}
		})
	}
}

// ── MSSQL ──

func TestDetectSQLError_MSSQL(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"unclosed quote", `Microsoft SQL Native Client error: Unclosed quotation mark`},
		{"sql server driver", `ODBC SQL Server Driver error`},
		{"sqlclient", `System.Data.SqlClient.SqlException: Incorrect syntax near`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := DetectSQLError(tc.body)
			if !r.Found || r.DBMS != "mssql" {
				t.Fatalf("expected mssql, got %+v", r)
			}
		})
	}
}

// ── Oracle ──

func TestDetectSQLError_Oracle(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"ORA-01756", `ORA-01756: quoted string not properly terminated`},
		{"ORA-00933", `ORA-00933: SQL command not properly ended`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := DetectSQLError(tc.body)
			if !r.Found || r.DBMS != "oracle" {
				t.Fatalf("expected oracle, got %+v", r)
			}
		})
	}
}

// ── SQLite ──

func TestDetectSQLError_SQLite(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"near syntax", `SQLITE_ERROR: near "'": syntax error`},
		{"unrecognized token", `unrecognized token: "'"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := DetectSQLError(tc.body)
			if !r.Found || r.DBMS != "sqlite" {
				t.Fatalf("expected sqlite, got %+v", r)
			}
		})
	}
}

func TestDetectSQLError_NoError(t *testing.T) {
	safe := []string{
		`<html><body>Hello World</body></html>`,
		`{"status":"ok","data":[]}`,
		`Product not found`,
		`Access denied`,
	}
	for _, body := range safe {
		if DetectSQLError(body).Found {
			t.Fatalf("false positive on: %s", body)
		}
	}
}

// ── Boolean blind ──

func TestResponsesDiffer_RealCases(t *testing.T) {
	cases := []struct {
		name      string
		baseline  string
		trueBody  string
		falseBody string
		trueCode  int
		falseCode int
		want      bool
	}{
		{
			name: "e-commerce listing", baseline: "total: 12 items for electronics",
			trueBody: "total: 847 items in database", falseBody: "total: 0 items",
			trueCode: 200, falseCode: 200, want: true,
		},
		{
			name: "login boolean", baseline: "Welcome user",
			trueBody: "Welcome admin", falseBody: "Invalid credentials",
			trueCode: 200, falseCode: 401, want: true,
		},
		{
			name: "same response", baseline: "ok",
			trueBody: "ok", falseBody: "ok",
			trueCode: 200, falseCode: 200, want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			differs, _ := ResponsesDiffer(tc.trueBody, tc.falseBody, tc.baseline, tc.trueCode, tc.falseCode, 200)
			if differs != tc.want {
				t.Fatalf("expected %v", tc.want)
			}
		})
	}
}

// ── UNION extraction ──

func TestDetectUnionSuccess_RealCases(t *testing.T) {
	cases := []struct {
		name     string
		baseline string
		body     string
		payload  string
	}{
		{"mysql version", `<html>results</html>`, `<html>8.0.32-MySQL Community Server</html>`, ""},
		{"postgresql", `Account balance`, `PostgreSQL 14.10 on x86_64`, ""},
		{"mssql", `{"invoices":[]}`, `{"db":"Microsoft SQL Server 2019"}`, ""},
		{"reflected payload only", `lang=fr`, `<html>lang=' UNION SELECT version(),NULL--</html>`, `' UNION SELECT version(),NULL--`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectUnionSuccess(tc.body, tc.baseline, tc.payload)
			want := tc.name != "reflected payload only"
			if got != want {
				t.Fatalf("expected %v, got %v", want, got)
			}
		})
	}
}

// ── DB leak ──

func TestDetectDBLeak_NoLeakOnStaticPage(t *testing.T) {
	baseline := `<html><body><p>Service i=144</p><span>1.0.0</span></body></html>`
	body := `<html><body><p>Service i=1 OR 1=1--</p><span>2.0.0</span></body></html>`
	if leak, _ := DetectDBLeak(body, baseline); leak {
		t.Fatalf("expected no leak on generic version numbers, got leak")
	}
}

func TestDetectDBLeak_RealCases(t *testing.T) {
	cases := []struct {
		name     string
		baseline string
		body     string
	}{
		{"extractvalue", `Report generated`, `XPATH syntax error: '~8.0.32-MySQL~'`},
		{"version string", `Product id=1`, `Result: 5.7.33-log`},
		{"db user", `ok`, `connected as root@localhost`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			leak, _ := DetectDBLeak(tc.body, tc.baseline)
			if !leak {
				t.Fatal("expected leak")
			}
		})
	}
}

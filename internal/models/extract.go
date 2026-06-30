package models

// DataType type de donnée extraite de la DB.
type DataType string

const (
	DataVersion  DataType = "version"
	DataDatabase DataType = "database"
	DataUser     DataType = "user"
	DataTables   DataType = "tables"
	DataColumns  DataType = "columns"
	DataDump     DataType = "dump"
)

// ExtractedData représente une donnée extraite de la base.
type ExtractedData struct {
	FindingURL string
	Parameter  string
	VulnType   VulnType
	DBMS       string
	DataType   DataType
	Value      string
	Payload    string
	Method     string // union, error, nosql
}

// ExtractionResult agrège les extractions pour une cible.
type ExtractionResult struct {
	Target      ScanTarget
	Extractions []ExtractedData
	Errors      []string
}

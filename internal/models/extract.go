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
	DataPII      DataType = "pii" // enregistrement utilisateur à risque
)

// PIIUser données personnelles extraites (format structuré).
type PIIUser struct {
	Nom           string `json:"nom,omitempty"`
	Prenom        string `json:"prenom,omitempty"`
	DateNaissance string `json:"date_naissance,omitempty"`
	Adresse       string `json:"adresse,omitempty"`
	Email         string `json:"email,omitempty"`
	Telephone     string `json:"telephone,omitempty"`
	IBAN          string `json:"iban,omitempty"`
	Table         string `json:"table,omitempty"`
}

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
	PII        *PIIUser `json:"pii,omitempty"`
}

// ExtractionResult agrège les extractions pour une cible.
type ExtractionResult struct {
	Target      ScanTarget
	Extractions []ExtractedData
	Errors      []string
}

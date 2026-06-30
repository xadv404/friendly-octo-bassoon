package models

// VulnType représente une vulnérabilité donnant accès à la base de données.
type VulnType string

const (
	SQLiError   VulnType = "sqli_error"
	SQLiBoolean VulnType = "sqli_boolean"
	SQLiTime    VulnType = "sqli_time"
	SQLiUnion   VulnType = "sqli_union"
	NoSQL       VulnType = "nosql"
)

// InjectionType alias rétrocompatible.
type InjectionType = VulnType

const (
	ErrorBased   = SQLiError
	BooleanBlind = SQLiBoolean
	TimeBlind    = SQLiTime
	UnionBased   = SQLiUnion
)

// VulnCategory regroupe les familles d'injection DB.
type VulnCategory string

const (
	CategorySQLi   VulnCategory = "sqli"
	CategoryNoSQL  VulnCategory = "nosql"
)

// ScanMode définit la profondeur du scan.
type ScanMode string

const (
	ScanFast ScanMode = "fast"
	ScanFull ScanMode = "full"
)

// Confidence indique le niveau de certitude d'une détection.
type Confidence string

const (
	Low       Confidence = "low"
	Medium    Confidence = "medium"
	High      Confidence = "high"
	Confirmed Confidence = "confirmed"
)

// ScanTarget décrit une cible à tester.
type ScanTarget struct {
	URL      string
	Method   string
	Params   map[string]string
	Data     map[string]string
	Headers  map[string]string
	Cookies  map[string]string
	JSONBody map[string]any
}

// Finding représente une injection DB détectée.
type Finding struct {
	URL            string
	Parameter      string
	Payload        string
	VulnType       VulnType
	Confidence     Confidence
	Evidence       string
	DBMS           string
	ResponseTimeMs float64
	StatusCode     int
}

func (f Finding) InjectionType() VulnType { return f.VulnType }

// ScanOptions configure le comportement du scanner.
type ScanOptions struct {
	Categories      []VulnCategory
	Techniques      []VulnType
	Mode            ScanMode
	IncludeWAF      bool
	CustomPayloads  []string
	TimeDelaySec    int
	TimeThresholdMs float64
	RateLimitMs     int
	TimeoutSec      int
	Threads         int
	Verbose         bool
	EarlyExit       bool
	AutoExtract     bool // extraire dès qu'une vuln est trouvée
	ExtractOnly     bool // mode extraction seul (pas de scan)
	ExtractAfter    bool // extraire après le scan sur toutes les findings
}

// ScanResult agrège les résultats d'un scan.
type ScanResult struct {
	Target         ScanTarget
	Findings       []Finding
	Extractions    []ExtractedData
	TestedParams   int
	TestedPayloads int
	Errors         []string
}

// TestJob décrit un test unitaire.
type TestJob struct {
	Param     string
	VulnType  VulnType
	Category  VulnCategory
	Payload   string
	PayloadB  string
	Priority  int
}

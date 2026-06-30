package models

// VulnType représente le type de vulnérabilité testée.
type VulnType string

const (
	SQLiError      VulnType = "sqli_error"
	SQLiBoolean    VulnType = "sqli_boolean"
	SQLiTime       VulnType = "sqli_time"
	SQLiUnion      VulnType = "sqli_union"
	XSS            VulnType = "xss"
	OpenRedirect   VulnType = "open_redirect"
	LFI            VulnType = "lfi"
	SSRF           VulnType = "ssrf"
)

// InjectionType est un alias rétrocompatible.
type InjectionType = VulnType

const (
	ErrorBased   = SQLiError
	BooleanBlind = SQLiBoolean
	TimeBlind    = SQLiTime
	UnionBased   = SQLiUnion
)

// VulnCategory regroupe les tests par famille.
type VulnCategory string

const (
	CategorySQLi     VulnCategory = "sqli"
	CategoryXSS      VulnCategory = "xss"
	CategoryRedirect VulnCategory = "redirect"
	CategoryLFI      VulnCategory = "lfi"
	CategorySSRF     VulnCategory = "ssrf"
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

// Finding représente une vulnérabilité potentielle détectée.
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

// InjectionType field alias for backward compat in output
func (f Finding) InjectionType() VulnType { return f.VulnType }

// ScanOptions configure le comportement du scanner.
type ScanOptions struct {
	Categories      []VulnCategory
	Techniques      []VulnType // filtre fin SQLi si categories contient sqli
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
}

// ScanResult agrège les résultats d'un scan.
type ScanResult struct {
	Target         ScanTarget
	Findings       []Finding
	TestedParams   int
	TestedPayloads int
	Errors         []string
}

// TestJob décrit un test unitaire à exécuter.
type TestJob struct {
	Param      string
	VulnType   VulnType
	Category   VulnCategory
	Payload    string
	PayloadB   string // pour boolean blind (payload faux)
	Priority   int
}

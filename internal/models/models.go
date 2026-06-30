package models

// InjectionType représente une technique de détection SQLi.
type InjectionType string

const (
	ErrorBased   InjectionType = "error_based"
	BooleanBlind InjectionType = "boolean_blind"
	TimeBlind    InjectionType = "time_blind"
	UnionBased   InjectionType = "union_based"
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
	InjectionType  InjectionType
	Confidence     Confidence
	Evidence       string
	DBMS           string
	ResponseTimeMs float64
	StatusCode     int
}

// ScanOptions configure le comportement du scanner.
type ScanOptions struct {
	Techniques      []InjectionType
	IncludeWAF      bool
	CustomPayloads  []string
	TimeDelaySec    int
	TimeThresholdMs float64
	RateLimitMs     int
	TimeoutSec      int
	Threads         int
	Verbose         bool
}

// ScanResult agrège les résultats d'un scan.
type ScanResult struct {
	Target          ScanTarget
	Findings        []Finding
	TestedParams    int
	TestedPayloads  int
	Errors          []string
}

package discover

// DiscoverBackendLabel décrit le backend discover actif (CLI).
func DiscoverBackendLabel(source Source) string {
	switch source {
	case SourceGoogle:
		return GoogleBackendLabel()
	case SourceDDG, SourceAuto:
		if HasDiscoverProxy() {
			return "duckduckgo + proxy BP"
		}
		return "duckduckgo (scraping)"
	case SourceBing:
		return "bing"
	default:
		return string(source)
	}
}

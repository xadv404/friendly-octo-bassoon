package discover

// DiscoverBackendLabel décrit le backend discover actif (CLI).
func DiscoverBackendLabel(source Source) string {
	switch source {
	case SourceGoogle, SourceAuto:
		return GoogleBackendLabel()
	case SourceDDG:
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

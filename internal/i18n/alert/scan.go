package alert

// ScanCompleteDetail format fin de scan massif (FR par défaut).
func ScanCompleteDetail(loc string, scanned, total, vulns, findings, newEmails int, stock string) string {
	labels := scanCompleteLabels{
		scanned:   "scanné:",
		vulns:     "vulns:",
		findings:  "findings:",
		newEmails: "nouveaux emails:",
	}
	if loc == "en" {
		labels = scanCompleteLabels{
			scanned:   "scanned:",
			vulns:     "vulns:",
			findings:  "findings:",
			newEmails: "new emails:",
		}
	}
	return formatScanComplete(scanned, total, vulns, findings, newEmails, stock, labels)
}

package main

import "regexp"

// Finding represents one detected potential secret.
type Finding struct {
	CommitHash string
	File       string
	LineText   string
	RuleName   string
}

// rule pairs a name with the pattern that detects it. Keeping them in
// a slice (instead of one-off if-statements) means adding a new rule
// is just adding one line here — nothing else in the file changes.
type rule struct {
	name    string
	pattern *regexp.Regexp
}

var rules = []rule{
	{
		name:    "aws-access-key",
		pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	},
	{
		name:    "github-token",
		pattern: regexp.MustCompile(`gh[pos]_[0-9A-Za-z]{36}`),
	},
	{
		name:    "google-api-key",
		pattern: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
	},
	{
		name:    "slack-token",
		pattern: regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`),
	},
	{
		name:    "private-key-header",
		pattern: regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`),
	},
	{
		name:    "generic-jwt",
		pattern: regexp.MustCompile(`eyJ[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+`),
	},
}

// scanForSecrets runs every known rule against every added line and
// returns everything that matches.
func scanForSecrets(lines []AddedLine) []Finding {
	var findings []Finding

	for _, l := range lines {
		for _, r := range rules {
			if r.pattern.MatchString(l.LineText) {
				findings = append(findings, Finding{
					CommitHash: l.CommitHash,
					File:       l.File,
					LineText:   l.LineText,
					RuleName:   r.name,
				})
			}
		}
	}

	return findings
}
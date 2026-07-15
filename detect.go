package main

import "regexp"

// Finding represents one detected potential secret.
type Finding struct {
	CommitHash string
	File       string
	LineText   string
	RuleName   string
}

// awsAccessKeyPattern matches AWS access key IDs, e.g. AKIAIOSFODNN7EXAMPLE
var awsAccessKeyPattern = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)

// scanForSecrets runs known secret patterns against every added line
// and returns everything that matches.
func scanForSecrets(lines []AddedLine) []Finding {
	var findings []Finding

	for _, l := range lines {
		if awsAccessKeyPattern.MatchString(l.LineText) {
			findings = append(findings, Finding{
				CommitHash: l.CommitHash,
				File:       l.File,
				LineText:   l.LineText,
				RuleName:   "aws-access-key",
			})
		}
	}

	return findings
}
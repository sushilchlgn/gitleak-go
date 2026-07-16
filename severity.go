package main

import (
	"os/exec"
	"strings"
)

// Severity levels, ordered from most to least urgent.
const (
	SeverityCritical = "CRITICAL" // still live in current code
	SeverityHigh     = "HIGH"     // removed from current code, but lives in history forever
)

// isStillInHEAD checks whether the given secret value still appears
// anywhere in the current working tree (i.e. `git grep` against HEAD).
func isStillInHEAD(repoPath string, value string) bool {
	cmd := exec.Command("git", "grep", "-F", "-q", value, "HEAD")
	cmd.Dir = repoPath

	err := cmd.Run()
	// git grep exits 0 if found, 1 if not found, >1 on actual error.
	return err == nil
}

// extractSecretValue pulls just the secret-looking substring out of a
// finding's full line, so we grep for the value itself, not the whole line.
func extractSecretValue(lineText string) string {
	matches := candidatePattern.FindStringSubmatch(lineText)
	if len(matches) > 1 {
		return matches[1]
	}
	return strings.TrimSpace(lineText)
}

// severityFor determines CRITICAL vs HIGH for a given finding based
// on whether its value is still present in the current HEAD.
func severityFor(repoPath string, lineText string) string {
	value := extractSecretValue(lineText)
	if value == "" {
		return SeverityHigh
	}
	if isStillInHEAD(repoPath, value) {
		return SeverityCritical
	}
	return SeverityHigh
}
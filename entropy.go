package main

import (
	"math"
	"regexp"
	"strings"
)

// shannonEntropy calculates the Shannon entropy of a string in bits
// per character. Higher = more random-looking. English words and
// normal code tend to sit under ~3.5. Random secrets (API keys,
// generated tokens) tend to sit at 4.0+.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}

	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// candidatePattern extracts quoted string-like values from a line,
// e.g. the right-hand side of `key = "..."` or `key: '...'`.
var candidatePattern = regexp.MustCompile(`["']([A-Za-z0-9+/=_\-]{16,})["']`)

// EntropyFinding represents a high-entropy string that didn't match
// any known regex rule but still looks suspicious.
type EntropyFinding struct {
	CommitHash string
	File       string
	LineText   string
	Value      string
	Entropy    float64
}

// scanForHighEntropy looks for high-randomness quoted strings in added
// lines. alreadyFlagged lets us skip lines the regex rules already
// caught, so we don't report the same secret twice under two names.
func scanForHighEntropy(lines []AddedLine, alreadyFlagged map[string]bool) []EntropyFinding {
	const entropyThreshold = 4.0
	const minLength = 16

	var findings []EntropyFinding

	for _, l := range lines {
		key := l.CommitHash + l.File + l.LineText
		if alreadyFlagged[key] {
			continue
		}

		matches := candidatePattern.FindAllStringSubmatch(l.LineText, -1)
		for _, m := range matches {
			value := m[1]
			if len(value) < minLength {
				continue
			}

			if isLikelyNotSecret(value) {
				continue
			}

			e := shannonEntropy(value)
			if e >= entropyThreshold {
				findings = append(findings, EntropyFinding{
					CommitHash: l.CommitHash,
					File:       l.File,
					LineText:   l.LineText,
					Value:      value,
					Entropy:    e,
				})
			}
		}
	}

	return findings
}

// isLikelyNotSecret filters out common false positives: URLs and
// path-like strings that are long but not actually random.
func isLikelyNotSecret(s string) bool {
	lower := strings.ToLower(s)

	if strings.Contains(lower, "http://") || strings.Contains(lower, "https://") {
		return true
	}
	if strings.Contains(s, "/") {
		slashCount := strings.Count(s, "/")
		if slashCount >= 2 {
			return true
		}
	}

	return false
}
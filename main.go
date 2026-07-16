package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type AddedLine struct {
	CommitHash string
	File       string
	LineText   string
}

// Report is the unified, JSON-serializable shape for every finding,
// whether it came from a regex rule or entropy scoring.
type Report struct {
	CommitHash string  `json:"commit_hash"`
	File       string  `json:"file"`
	Line       string  `json:"line"`
	RuleName   string  `json:"rule_name"`
	Entropy    float64 `json:"entropy,omitempty"`
	Severity   string  `json:"severity"`
}

func main() {
	jsonOutput := flag.Bool("json", false, "output findings as JSON instead of plain text")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("usage: gitleak-go [-json] <path-to-git-repo>")
		os.Exit(1)
	}
	repoPath := args[0]

	lines, err := walkHistory(repoPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	findings := scanForSecrets(lines)

	alreadyFlagged := make(map[string]bool)
	for _, f := range findings {
		key := f.CommitHash + f.File + f.LineText
		alreadyFlagged[key] = true
	}

	entropyFindings := scanForHighEntropy(lines, alreadyFlagged)

	var reports []Report
	for _, f := range findings {
		reports = append(reports, Report{
			CommitHash: f.CommitHash,
			File:       f.File,
			Line:       f.LineText,
			RuleName:   f.RuleName,
			Severity:   severityFor(repoPath, f.LineText),
		})
	}
	for _, e := range entropyFindings {
		reports = append(reports, Report{
			CommitHash: e.CommitHash,
			File:       e.File,
			Line:       e.LineText,
			RuleName:   "high-entropy",
			Entropy:    e.Entropy,
			Severity:   severityFor(repoPath, e.LineText),
		})
	}

	if *jsonOutput {
		out, err := json.MarshalIndent(reports, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "error marshaling JSON:", err)
			os.Exit(1)
		}
		fmt.Println(string(out))
		return
	}

	fmt.Println("=== Pattern matches ===")
	for _, f := range findings {
		sev := severityFor(repoPath, f.LineText)
		fmt.Printf("[%s] %s: (%s) [%s] %s\n", f.CommitHash[:7], f.File, f.RuleName, sev, f.LineText)
	}

	fmt.Println("\n=== High-entropy candidates (no known pattern) ===")
	for _, e := range entropyFindings {
		sev := severityFor(repoPath, e.LineText)
		fmt.Printf("[%s] %s: (entropy %.2f) [%s] %s\n", e.CommitHash[:7], e.File, e.Entropy, sev, e.LineText)
	}

	fmt.Printf("\nadded lines scanned: %d | pattern findings: %d | entropy findings: %d\n",
		len(lines), len(findings), len(entropyFindings))
}

// walkHistory runs `git log -p --all` inside repoPath and parses the
// output into a flat list of added lines, each tagged with the commit
// hash and file it belongs to.
func walkHistory(repoPath string) ([]AddedLine, error) {
	cmd := exec.Command("git", "log", "-p", "--all", "--no-color")
	cmd.Dir = repoPath

	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("git log failed to start (is %q a git repo?): %w", repoPath, err)
	}

	var results []AddedLine
	var currentCommit string
	var currentFile string

	scanner := bufio.NewScanner(out)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()

		switch {
		case strings.HasPrefix(line, "commit "):
			currentCommit = strings.TrimSpace(strings.TrimPrefix(line, "commit "))

		case strings.HasPrefix(line, "+++ "):
			f := strings.TrimPrefix(line, "+++ ")
			f = strings.TrimPrefix(f, "b/")
			currentFile = f

		case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
			text := strings.TrimPrefix(line, "+")
			if strings.TrimSpace(text) == "" {
				continue
			}
			results = append(results, AddedLine{
				CommitHash: currentCommit,
				File:       currentFile,
				LineText:   text,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning git log output: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("git log exited with error: %w", err)
	}

	return results, nil
}
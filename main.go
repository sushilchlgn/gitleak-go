package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// AddedLine represents one line added in one commit's diff.
type AddedLine struct {
	CommitHash string
	File       string
	LineText   string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: gitleak-go <path-to-git-repo>")
		os.Exit(1)
	}
	repoPath := os.Args[1]

	lines, err := walkHistory(repoPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	findings := scanForSecrets(lines)

	for _, f := range findings {
		fmt.Printf("[%s] %s: (%s) %s\n", f.CommitHash[:7], f.File, f.RuleName, f.LineText)
	}
	fmt.Printf("\nadded lines scanned: %d | findings: %d\n", len(lines), len(findings))
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
package stego

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type StegoFinding struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	ChannelType string `json:"channel_type"`
	Snippet     string `json:"snippet"`
}

type StegoResult struct {
	Target   string         `json:"target"`
	Findings []StegoFinding `json:"findings"`
	IsClean  bool           `json:"is_clean"`
}

var zeroWidthRegex = regexp.MustCompile(`[\x{200B}\x{200C}\x{200D}\x{FEFF}\x{2060}]`)

func ScanStego(targetPath string) (StegoResult, error) {
	cleanPath := filepath.Clean(targetPath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return StegoResult{}, fmt.Errorf("stat target path: %w", err)
	}

	var findings []StegoFinding

	scanFile := func(path string) error {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
			if zeroWidthRegex.MatchString(line) {
				findings = append(findings, StegoFinding{
					File:        path,
					Line:        lineNum,
					ChannelType: "zero-width-unicode-steganography",
					Snippet:     strings.TrimSpace(line),
				})
			}
		}
		return scanner.Err()
	}

	if !info.IsDir() {
		if err := scanFile(cleanPath); err != nil {
			return StegoResult{}, err
		}
	} else {
		_ = filepath.Walk(cleanPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".md" || ext == ".txt" || ext == ".json" || ext == ".py" || ext == ".js" {
				_ = scanFile(path)
			}
			return nil
		})
	}

	return StegoResult{
		Target:   cleanPath,
		Findings: findings,
		IsClean:  len(findings) == 0,
	}, nil
}

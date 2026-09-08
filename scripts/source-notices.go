// Collect license-bearing comment groups from selected Go build inputs.
package main

import (
	"encoding/json"
	"fmt"
	"go/scanner"
	"go/token"
	"os"
	"regexp"
)

type sourceInput struct {
	Path      string `json:"path"`
	Component string `json:"component"`
	File      string `json:"file"`
}

var noticePattern = regexp.MustCompile(`(?i)\bcopyright\b|\blicen[cs](?:e|ed|es|ing)\b|\bpermission\b|\bredistribut|\bpublic domain\b|SPDX-License-Identifier`)

func commentNotices(src []byte) ([]string, error) {
	files := token.NewFileSet()
	file := files.AddFile("source", -1, len(src))
	var scan scanner.Scanner
	invalid := false
	scan.Init(file, src, func(token.Position, string) { invalid = true }, scanner.ScanComments)
	start, end := -1, 0
	var notices []string
	flush := func() {
		if start >= 0 && noticePattern.Match(src[start:end]) {
			notices = append(notices, string(src[start:end]))
		}
		start = -1
	}
	for {
		pos, kind, literal := scan.Scan()
		if kind == token.COMMENT {
			if start < 0 {
				start = file.Offset(pos)
			}
			// scanner normalizes CRLF in comment literals. Find the original
			// byte boundary to preserve upstream text exactly.
			offset := file.Offset(pos)
			if len(literal) >= 2 && literal[:2] == "//" {
				end = offset
				for end < len(src) && src[end] != '\n' {
					end++
				}
			} else {
				end = offset + 2
				for end+1 < len(src) && !(src[end] == '*' && src[end+1] == '/') {
					end++
				}
				end += 2
				if end > len(src) {
					invalid = true
					end = len(src)
				}
			}
		} else {
			flush()
		}
		if kind == token.EOF {
			break
		}
	}
	if invalid {
		return nil, fmt.Errorf("invalid Go source while collecting notices")
	}
	return notices, nil
}

func run() error {
	var inputs []sourceInput
	if err := json.NewDecoder(os.Stdin).Decode(&inputs); err != nil {
		return fmt.Errorf("invalid source notice input")
	}
	result := map[string]string{}
	for _, input := range inputs {
		src, err := os.ReadFile(input.Path)
		if err != nil {
			return fmt.Errorf("cannot read selected source for notices")
		}
		groups, err := commentNotices(src)
		if err != nil {
			return err
		}
		for _, group := range groups {
			result[input.Component] += "\n--- " + input.File + " ---\n" + group + "\n"
		}
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

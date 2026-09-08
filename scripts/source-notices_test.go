package main

import "testing"

func TestCommentNotices(t *testing.T) {
	src := []byte("// Copyright Someone\r\n// Permission and terms.\r\npackage example\nconst s = `// Copyright in a string`\n/* License text\r\nwith terms. */\nvar n = 1 // ordinary comment\n// Copyright Next\n// complete terms\nvar x = 2\n")
	got, err := commentNotices(src)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"// Copyright Someone\r\n// Permission and terms.\r", "/* License text\r\nwith terms. */", "// Copyright Next\n// complete terms"}
	if len(got) != len(want) {
		t.Fatalf("got %d groups, want %d: %q", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("group %d differs: %q", i, got[i])
		}
	}
}

func TestCommentNoticesRejectsMalformedSource(t *testing.T) {
	if _, err := commentNotices([]byte("package example\n/* Copyright unterminated")); err == nil {
		t.Fatal("malformed source accepted")
	}
}

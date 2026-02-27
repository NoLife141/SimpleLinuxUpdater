package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var inlineStyleBlockRe = regexp.MustCompile(`(?is)<style\b`)
var scriptTagRe = regexp.MustCompile(`(?is)<script\b([^>]*)>`)
var hasScriptSrcRe = regexp.MustCompile(`(?i)\bsrc\s*=`)
var inlineEventAttrRe = regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
var inlineStyleAttrRe = regexp.MustCompile(`(?i)\sstyle\s*=`)

func TestTemplatesStrictCSPCompliance(t *testing.T) {
	t.Parallel()

	type templateCheck struct {
		path             string
		requiredContains []string
	}

	checks := []templateCheck{
		{
			path: "templates/setup.html",
			requiredContains: []string{
				`href="/static/css/base.css"`,
				`href="/static/css/setup.css"`,
				`src="/static/js/common.js"`,
				`src="/static/js/setup.js"`,
			},
		},
		{
			path: "templates/login.html",
			requiredContains: []string{
				`href="/static/css/base.css"`,
				`href="/static/css/login.css"`,
				`src="/static/js/common.js"`,
				`src="/static/js/login.js"`,
			},
		},
		{
			path: "templates/index.html",
			requiredContains: []string{
				`href="/static/css/base.css"`,
				`href="/static/css/index.css"`,
				`src="/static/auth.js"`,
				`src="/static/js/common.js"`,
				`src="/static/js/index.js"`,
			},
		},
		{
			path: "templates/manage.html",
			requiredContains: []string{
				`href="/static/css/base.css"`,
				`href="/static/css/manage.css"`,
				`src="/static/auth.js"`,
				`src="/static/js/common.js"`,
				`src="/static/js/manage.js"`,
			},
		},
		{
			path: "templates/observability.html",
			requiredContains: []string{
				`href="/static/css/base.css"`,
				`href="/static/css/observability.css"`,
				`src="/static/auth.js"`,
				`src="/static/js/common.js"`,
				`src="/static/js/observability.js"`,
			},
		},
	}

	for _, tc := range checks {
		t.Run(filepath.Base(tc.path), func(t *testing.T) {
			t.Parallel()

			raw, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatalf("ReadFile(%q) error: %v", tc.path, err)
			}
			content := string(raw)

			if inlineStyleBlockRe.MatchString(content) {
				t.Fatalf("%s contains inline <style> block; strict CSP requires external CSS", tc.path)
			}
			if inlineEventAttrRe.MatchString(content) {
				t.Fatalf("%s contains inline on* event handlers; strict CSP requires JS event listeners", tc.path)
			}
			if inlineStyleAttrRe.MatchString(content) {
				t.Fatalf("%s contains inline style= attributes; strict CSP requires CSS classes", tc.path)
			}

			matches := scriptTagRe.FindAllStringSubmatch(content, -1)
			for _, match := range matches {
				attrs := ""
				if len(match) > 1 {
					attrs = match[1]
				}
				if !hasScriptSrcRe.MatchString(attrs) {
					t.Fatalf("%s contains inline <script> block; strict CSP requires external scripts", tc.path)
				}
			}

			for _, required := range tc.requiredContains {
				if !strings.Contains(content, required) {
					t.Fatalf("%s missing required asset reference %q", tc.path, required)
				}
			}
		})
	}
}

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

var inlineStyleBlockRe = regexp.MustCompile(`(?is)<style\b`)
var scriptTagRe = regexp.MustCompile(`(?is)<script\b([^>]*)>`)
var hasScriptSrcRe = regexp.MustCompile(`(?i)\bsrc\s*=`)
var inlineEventAttrRe = regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
var inlineStyleAttrRe = regexp.MustCompile(`(?i)\sstyle\s*=`)

func assetAttributeRe(asset string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)\b(?:href|src)\s*=\s*["'][^"']*` + regexp.QuoteMeta(asset) + `(?:\?[^"']*)?["']`)
}

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
				`/static/css/base.css`,
				`/static/css/auth-common.css`,
				`/static/css/setup.css`,
				`/static/js/common.js`,
				`/static/js/setup.js`,
			},
		},
		{
			path: "templates/login.html",
			requiredContains: []string{
				`/static/css/base.css`,
				`/static/css/auth-common.css`,
				`/static/js/common.js`,
				`/static/js/login.js`,
			},
		},
		{
			path: "templates/index.html",
			requiredContains: []string{
				`/static/css/base.css`,
				`/static/css/index.css`,
				`/static/auth.js`,
				`/static/js/common.js`,
				`/static/js/index.js`,
			},
		},
		{
			path: "templates/manage.html",
			requiredContains: []string{
				`/static/css/base.css`,
				`/static/css/manage.css`,
				`/static/auth.js`,
				`/static/js/common.js`,
				`/static/js/manage.js`,
			},
		},
		{
			path: "templates/observability.html",
			requiredContains: []string{
				`/static/css/base.css`,
				`/static/css/observability.css`,
				`/static/auth.js`,
				`/static/js/common.js`,
				`/static/js/observability.js`,
			},
		},
		{
			path: "templates/admin.html",
			requiredContains: []string{
				`/static/css/base.css`,
				`/static/css/admin.css`,
				`/static/auth.js`,
				`/static/js/common.js`,
				`/static/js/admin.js`,
			},
		},
	}

	for _, tc := range checks {
		tc := tc
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
				if !assetAttributeRe(required).MatchString(content) {
					t.Fatalf("%s missing required asset attribute reference matching %q", tc.path, required)
				}
			}
		})
	}
}

func TestMaintenancePageStrictCSPCompliance(t *testing.T) {
	t.Parallel()

	content := maintenancePageHTML()
	if inlineStyleBlockRe.MatchString(content) {
		t.Fatalf("maintenance page contains inline <style> block; strict CSP requires external CSS")
	}
	if inlineEventAttrRe.MatchString(content) {
		t.Fatalf("maintenance page contains inline on* event handlers; strict CSP requires JS event listeners")
	}
	if inlineStyleAttrRe.MatchString(content) {
		t.Fatalf("maintenance page contains inline style= attributes; strict CSP requires CSS classes")
	}
	matches := scriptTagRe.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		attrs := ""
		if len(match) > 1 {
			attrs = match[1]
		}
		if !hasScriptSrcRe.MatchString(attrs) {
			t.Fatalf("maintenance page contains inline <script> block; strict CSP requires external scripts")
		}
	}
	for _, required := range []string{"/static/css/maintenance.css", "/static/js/maintenance.js"} {
		if !assetAttributeRe(required).MatchString(content) {
			t.Fatalf("maintenance page missing required asset attribute reference matching %q", required)
		}
	}
}

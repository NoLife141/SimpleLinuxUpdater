package app

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestParseTrustedProxies(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{name: "empty", raw: "", want: nil},
		{name: "none", raw: " none ", want: nil},
		{name: "trim dedupe", raw: " 127.0.0.1, 10.0.0.0/8,127.0.0.1,, ", want: []string{"127.0.0.1", "10.0.0.0/8"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseTrustedProxies(tt.raw); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseTrustedProxies(%q) = %#v, want %#v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestNewRouterWrapsTrustedProxyErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)
	_, err := NewRouter(RouterConfig{
		TrustedProxies: func() []string { return []string{"definitely-not-a-proxy"} },
		TemplatesGlob:  testTemplatesGlob(t),
		StaticRoot:     t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "failed to configure trusted proxies") {
		t.Fatalf("NewRouter() error = %v, want wrapped trusted proxy error", err)
	}
}

func TestNewRouterInitializesInOrder(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var calls []string
	router, err := NewRouter(RouterConfig{
		TrustedProxies: func() []string { return nil },
		InitializeMaintenance: func() error {
			calls = append(calls, "maintenance")
			return nil
		},
		InitializeJobs: func() error {
			calls = append(calls, "jobs")
			return nil
		},
		InitializeSessions: func() error {
			calls = append(calls, "sessions")
			return nil
		},
		TemplatesGlob: testTemplatesGlob(t),
		StaticRoot:    t.TempDir(),
		RegisterRoutes: func(r *gin.Engine) error {
			calls = append(calls, "routes")
			r.GET("/ok", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewRouter() error = %v", err)
	}
	if router == nil {
		t.Fatalf("NewRouter() returned nil router")
	}
	want := []string{"maintenance", "jobs", "sessions", "routes"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %#v, want %#v", calls, want)
	}
}

func TestNewRouterInstallsMiddlewareBeforeRouteRegistration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router, err := NewRouter(RouterConfig{
		TrustedProxies: func() []string { return nil },
		GlobalMiddleware: []gin.HandlerFunc{
			func(c *gin.Context) {
				c.Header("X-App-Shell", "middleware")
				c.Next()
			},
		},
		TemplatesGlob: testTemplatesGlob(t),
		StaticRoot:    t.TempDir(),
		RegisterRoutes: func(r *gin.Engine) error {
			r.GET("/middleware", func(c *gin.Context) {
				c.String(http.StatusOK, "ok")
			})
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewRouter() error = %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/middleware", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("X-App-Shell"); got != "middleware" {
		t.Fatalf("middleware header = %q, want middleware", got)
	}
}

func TestNewRouterReturnsRouteRegistrationErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)
	wantErr := errors.New("route registration failed")
	_, err := NewRouter(RouterConfig{
		TrustedProxies: func() []string { return nil },
		TemplatesGlob:  testTemplatesGlob(t),
		StaticRoot:     t.TempDir(),
		RegisterRoutes: func(*gin.Engine) error {
			return wantErr
		},
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("NewRouter() error = %v, want %v", err, wantErr)
	}
}

func TestNewRouterUsesDefaultTemplateAndStaticPaths(t *testing.T) {
	gin.SetMode(gin.TestMode)
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "templates", "index.html"), "{{define \"index.html\"}}ok{{end}}")
	writeTestFile(t, filepath.Join(root, "static", "app.txt"), "static ok")
	t.Chdir(root)

	router, err := NewRouter(RouterConfig{
		TrustedProxies: func() []string { return nil },
		RegisterRoutes: func(r *gin.Engine) error {
			r.GET("/", func(c *gin.Context) {
				c.HTML(http.StatusOK, "index.html", nil)
			})
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewRouter() error = %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/static/app.txt", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "static ok" {
		t.Fatalf("static response = %d %q, want 200 static ok", rec.Code, rec.Body.String())
	}
}

func testTemplatesGlob(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "templates", "index.html"), "{{define \"index.html\"}}ok{{end}}")
	return filepath.Join(root, "templates", "*")
}

func writeTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("create test dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write test file: %v", err)
	}
}

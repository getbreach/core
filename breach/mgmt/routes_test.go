//go:build mgmt

package mgmt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// PUT /routes is the one verb that forwards a caller-supplied JSON DOCUMENT to a
// tool, rather than a name matched against an allow-list. These tests pin the two
// things that makes load-bearing: the document is base64'd (so nothing in it can
// reach a shell) and a non-object is refused here rather than in sing-box, where
// it would surface as a restart loop on the server.

// fakeTools writes a stub `set-routes` that records its argv, and returns the
// bin dir plus the path it records to.
func fakeTools(t *testing.T) (binDir, recordPath string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stub tool is a shell script")
	}
	dir := t.TempDir()
	rec := filepath.Join(dir, "argv")
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' \"$1\" > %s\n", rec)
	if err := os.WriteFile(filepath.Join(dir, "set-routes"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir, rec
}

func routesRequest(t *testing.T, body string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	binDir, rec := fakeTools(t)
	s := &server{secret: "s3cr3t", confDir: t.TempDir(), binDir: binDir}

	req := httptest.NewRequest(http.MethodPut, "/s3cr3t/routes", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	arg, err := os.ReadFile(rec)
	if err != nil {
		return w, "" // tool never ran
	}
	return w, string(arg)
}

func TestRoutesPassesTheObjectBase64Encoded(t *testing.T) {
	// A route object holding shell metacharacters: if anything ever built a
	// command string instead of an argv, this is what would break out.
	route := `{"final":"direct","rules":[{"domain_suffix":["$(id).example;rm -rf /"],"action":"reject"}]}`
	w, arg := routesRequest(t, `{"route":`+route+`}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	decoded, err := base64.StdEncoding.DecodeString(arg)
	if err != nil {
		t.Fatalf("set-routes got a non-base64 argument %q: %v", arg, err)
	}
	var got, want map[string]any
	if err := json.Unmarshal(decoded, &got); err != nil {
		t.Fatalf("decoded argument is not JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(route), &want); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("route round-tripped as %v, want %v", got, want)
	}
}

func TestRoutesClear(t *testing.T) {
	w, arg := routesRequest(t, `{"clear":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	if arg != "clear" {
		t.Fatalf("set-routes got %q, want \"clear\"", arg)
	}
}

// A bare array or string is valid JSON but not a valid sing-box "route". Caught
// here it is a 400; passed through it would be written to routes.json and only
// fail when sing-box reloads — i.e. as an exit that stops working.
func TestRoutesRejectsNonObject(t *testing.T) {
	for _, body := range []string{
		`{"route":[]}`,
		`{"route":"direct"}`,
		`{"route":null}`,
		`{}`,
		`not json`,
	} {
		t.Run(body, func(t *testing.T) {
			w, arg := routesRequest(t, body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", w.Code, w.Body.String())
			}
			if arg != "" {
				t.Fatalf("set-routes ran with %q — it should not have run at all", arg)
			}
		})
	}
}

// The secret gates /routes exactly like every other verb.
func TestRoutesNeedsTheSecret(t *testing.T) {
	binDir, rec := fakeTools(t)
	s := &server{secret: "s3cr3t", confDir: t.TempDir(), binDir: binDir}

	req := httptest.NewRequest(http.MethodPut, "/wrong/routes", strings.NewReader(`{"clear":true}`))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if _, err := os.ReadFile(rec); err == nil {
		t.Fatal("set-routes ran for a request with the wrong secret")
	}
}

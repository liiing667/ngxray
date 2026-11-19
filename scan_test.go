// Acceptance tests for the ngxray scanner CLI.
//
// The scanner itself is scan.py; these tests exercise its fail-closed
// contract through the CLI so that `go test ./...` validates the same
// conclusion the scanner reports: clean, findings, indeterminate and
// canceled are distinct outcomes, and only a fully determined clean scan
// exits 0.

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	exitClean         = 0
	exitFindings      = 1
	exitIndeterminate = 2
	exitCanceled      = 3
)

func haveParser() bool {
	_, err := os.Stat(filepath.Join("build", "nginx_conf_parse"))
	return err == nil
}

func havePcreGroups() bool {
	_, err := os.Stat(filepath.Join("build", "pcre_groups"))
	return err == nil
}

func requireParser(t *testing.T) {
	t.Helper()
	if !haveParser() {
		t.Skip("build/nginx_conf_parse not built; run make first")
	}
}

// runScanner invokes scan.py and returns exit code, stdout and stderr.
func runScanner(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command("python3", append([]string{"scan.py"}, args...)...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err == nil {
		return 0, outBuf.String(), errBuf.String()
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), outBuf.String(), errBuf.String()
	}
	t.Fatalf("cannot run scan.py: %v", err)
	return -1, "", ""
}

func writeTempConf(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireStatus(t *testing.T, stderr, status string) {
	t.Helper()
	if !strings.Contains(stderr, "status: "+status) {
		t.Fatalf("expected status %q in stderr, got:\n%s", status, stderr)
	}
}

// The embedded rule test suite must keep passing (compatibility).
func TestEmbeddedRuleSuite(t *testing.T) {
	requireParser(t)
	if !havePcreGroups() {
		t.Skip("build/pcre_groups not built; run make first")
	}
	code, out, _ := runScanner(t, "", "--test")
	if code != 0 {
		t.Fatalf("scan.py --test exited %d:\n%s", code, out)
	}
}

// A legitimate config with no matches is clean and exits 0.
func TestCleanConfig(t *testing.T) {
	requireParser(t)
	conf := writeTempConf(t, "server { listen 80; location / { return 200 \"ok\"; } }\n")
	code, _, stderr := runScanner(t, "", conf)
	if code != exitClean {
		t.Fatalf("clean config: exit = %d, want 0\nstderr: %s", code, stderr)
	}
	requireStatus(t, stderr, "clean")
	if !strings.Contains(stderr, "No vulnerabilities found.") {
		t.Fatalf("clean config should report no vulnerabilities:\n%s", stderr)
	}
}

// A config matching a rule produces findings and exits non-zero.
func TestVulnerableConfig(t *testing.T) {
	requireParser(t)
	conf := writeTempConf(t,
		"server { location ~ ^/api/(.*)$ { rewrite ^/api/(.*)$ /internal?migrated=true; set $ep $1; } }\n")
	code, stdout, stderr := runScanner(t, "", conf)
	if code != exitFindings {
		t.Fatalf("vulnerable config: exit = %d, want %d\nstderr: %s", code, exitFindings, stderr)
	}
	requireStatus(t, stderr, "findings")
	if !strings.Contains(stdout, "rewrite-is-args") {
		t.Fatalf("expected rewrite-is-args finding, got:\n%s", stdout)
	}
}

// A config that cannot be parsed is indeterminate, never clean.
func TestParseFailureFailsClosed(t *testing.T) {
	requireParser(t)
	conf := writeTempConf(t, "server { listen 80; {{{\n")
	code, _, stderr := runScanner(t, "", conf)
	if code != exitIndeterminate {
		t.Fatalf("unparseable config: exit = %d, want %d\nstderr: %s", code, exitIndeterminate, stderr)
	}
	requireStatus(t, stderr, "indeterminate")
	if strings.Contains(stderr, "No vulnerabilities found.") {
		t.Fatalf("unparseable config must not be reported as clean:\n%s", stderr)
	}
}

// A JSONL error record (parser reported a failure upstream) fails closed.
func TestJSONLErrorRecordFailsClosed(t *testing.T) {
	rec := `{"file":"broken.conf","error":true,"config":[]}` + "\n"
	code, _, stderr := runScanner(t, rec, "--jsonl", "-")
	if code != exitIndeterminate {
		t.Fatalf("jsonl error record: exit = %d, want %d\nstderr: %s", code, exitIndeterminate, stderr)
	}
	requireStatus(t, stderr, "indeterminate")
}

// A JSONL record without a "config" field must not be treated as an
// empty (clean) config.
func TestJSONLMissingConfigFailsClosed(t *testing.T) {
	rec := `{"file":"truncated.conf"}` + "\n"
	code, _, stderr := runScanner(t, rec, "--jsonl", "-")
	if code != exitIndeterminate {
		t.Fatalf("jsonl missing config: exit = %d, want %d\nstderr: %s", code, exitIndeterminate, stderr)
	}
	requireStatus(t, stderr, "indeterminate")
}

// A malformed AST node (attacker-controlled JSONL) is indeterminate.
func TestJSONLMalformedASTFailsClosed(t *testing.T) {
	rec := `{"file":"evil.conf","config":[{"args":[]}]}` + "\n"
	code, _, stderr := runScanner(t, rec, "--jsonl", "-")
	if code != exitIndeterminate {
		t.Fatalf("jsonl malformed AST: exit = %d, want %d\nstderr: %s", code, exitIndeterminate, stderr)
	}
	requireStatus(t, stderr, "indeterminate")
}

// A truncated JSONL stream means the producer was cut off: the partial
// results must be reported as canceled, not as a completed clean scan.
func TestJSONLTruncatedStreamIsCanceled(t *testing.T) {
	partial := "{\"file\":\"cut.conf\",\"config\":["
	code, _, stderr := runScanner(t, partial, "--jsonl", "-")
	if code != exitCanceled {
		t.Fatalf("truncated jsonl: exit = %d, want %d\nstderr: %s", code, exitCanceled, stderr)
	}
	requireStatus(t, stderr, "canceled")
}

// Invalid rules (missing required fields, unknown keys) fail closed.
func TestInvalidRuleFailsClosed(t *testing.T) {
	dir := t.TempDir()
	rule := `{"severity":"LOW","message":"x","match":[{"directive":"set"}]}`
	if err := os.WriteFile(filepath.Join(dir, "no-id.json"), []byte(rule), 0o644); err != nil {
		t.Fatal(err)
	}
	conf := writeTempConf(t, "server { listen 80; }\n")
	code, _, _ := runScanner(t, "", "--rules", dir, conf)
	if code != exitIndeterminate {
		t.Fatalf("rule missing id: exit = %d, want %d", code, exitIndeterminate)
	}
}

// A rule with an unknown condition key must be rejected, not silently
// weakened.
func TestUnknownConditionKeyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	rule := `{"id":"x","severity":"LOW","message":"x",` +
		`"match":[{"directive":"set","args":{"1":{"contain":"a"}}}]}`
	if err := os.WriteFile(filepath.Join(dir, "typo.json"), []byte(rule), 0o644); err != nil {
		t.Fatal(err)
	}
	conf := writeTempConf(t, "server { listen 80; }\n")
	code, _, _ := runScanner(t, "", "--rules", dir, conf)
	if code != exitIndeterminate {
		t.Fatalf("unknown condition key: exit = %d, want %d", code, exitIndeterminate)
	}
}

// An empty rules directory cannot prove anything: fail closed.
func TestEmptyRulesDirFailsClosed(t *testing.T) {
	dir := t.TempDir()
	conf := writeTempConf(t, "server { listen 80; }\n")
	code, _, _ := runScanner(t, "", "--rules", dir, conf)
	if code != exitIndeterminate {
		t.Fatalf("empty rules dir: exit = %d, want %d", code, exitIndeterminate)
	}
}

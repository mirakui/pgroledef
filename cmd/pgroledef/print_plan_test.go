package main

import (
	"regexp"
	"strings"
	"testing"

	"github.com/mirakui/pgroledef/internal/config"
	"github.com/mirakui/pgroledef/internal/plan"
	"github.com/mirakui/pgroledef/internal/termcolor"
)

func samplePlan(engine config.Engine) *plan.Plan {
	p := &plan.Plan{
		Dialect: plan.DialectFor(engine),
		RoleDiffs: []plan.RoleDiff{
			{Name: "worker", Created: true, LoginChanged: true, LoginAfter: true},
		},
		Statements: []plan.Statement{
			{Database: "", SQL: `CREATE ROLE "worker" WITH LOGIN`},
			{Database: "app", SQL: `REVOKE DELETE ON TABLE "public"."orders" FROM "grp_viewer"`, Destructive: true, Note: "privilege not declared"},
		},
	}
	return p
}

const wantPlainPlan = `+ role "worker"
  + login:     true

SQL:
  -- cluster
  + CREATE ROLE "worker" WITH LOGIN;
  -- app
  - REVOKE DELETE ON TABLE "public"."orders" FROM "grp_viewer";  -- privilege not declared

Plan: 2 statement(s), 1 destructive.
`

func TestPrintPlanPlain(t *testing.T) {
	var b strings.Builder
	printPlan(&b, termcolor.New(false), samplePlan(config.EngineAuroraPostgres))
	if b.String() != wantPlainPlan {
		t.Errorf("plan output mismatch\n--- got ---\n%s\n--- want ---\n%s", b.String(), wantPlainPlan)
	}
}

// TestPrintPlanColoredStripsToPlain is the regression guard for the whole
// output: colour may only wrap the text, never change it.
func TestPrintPlanColoredStripsToPlain(t *testing.T) {
	for _, engine := range []config.Engine{config.EngineAuroraPostgres, config.EngineDSQL} {
		p := samplePlan(engine)
		var plain, colored strings.Builder
		printPlan(&plain, termcolor.New(false), p)
		printPlan(&colored, termcolor.New(true), p)
		if got := stripANSI(colored.String()); got != plain.String() {
			t.Errorf("%s: stripped colour output differs from plain\n--- got ---\n%s\n--- want ---\n%s", engine, got, plain.String())
		}
		if !strings.Contains(colored.String(), "\x1b[") {
			t.Errorf("%s: coloured output has no escape sequences", engine)
		}
	}
}

func TestPrintPlanColorMarks(t *testing.T) {
	var b strings.Builder
	printPlan(&b, termcolor.New(true), samplePlan(config.EngineDSQL))
	got := b.String()
	for _, want := range []string{
		"\x1b[32m+ CREATE ROLE",                              // added statement: green
		"\x1b[31m- REVOKE DELETE",                            // destructive statement: red
		"\x1b[2m-- cluster\x1b[0m",                           // database label: dim
		"\x1b[2m-- privilege not declared\x1b[0m",            // trailing reason: dim
		"\x1b[1mSQL:\x1b[0m",                                 // heading: bold
		"\x1b[1mPlan: 2 statement(s), 1 destructive.\x1b[0m", // summary: bold
		"\x1b[33mNote: dsql applies one statement",           // non-atomic warning: yellow
		"\x1b[1;32m+ role \"worker\"\x1b[0m",                 // role heading: bold + green, one sequence
	} {
		if !strings.Contains(got, want) {
			t.Errorf("coloured plan is missing %q\n%s", want, got)
		}
	}
}

func TestPrintPlanEmpty(t *testing.T) {
	var plain, colored strings.Builder
	printPlan(&plain, termcolor.New(false), &plan.Plan{})
	printPlan(&colored, termcolor.New(true), &plan.Plan{})
	const want = "No changes. The database matches the declaration.\n"
	if plain.String() != want {
		t.Errorf("got %q, want %q", plain.String(), want)
	}
	if colored.String() != "\x1b[1m"+strings.TrimSuffix(want, "\n")+"\x1b[0m\n" {
		t.Errorf("empty plan should be bold, got %q", colored.String())
	}
}

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(s string) string { return ansiRE.ReplaceAllString(s, "") }

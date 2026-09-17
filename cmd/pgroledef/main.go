// Command pgroledef manages PostgreSQL roles and privileges declaratively from jsonnet.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mirakui/pgroledef/internal/awsauth"
	"github.com/mirakui/pgroledef/internal/catalog"
	"github.com/mirakui/pgroledef/internal/config"
	"github.com/mirakui/pgroledef/internal/jsonnetx"
	"github.com/mirakui/pgroledef/internal/plan"
)

var (
	flagFile        string
	flagExtStrs     []string
	flagJPaths      []string
	flagDSN         string
	flagOut         string
	flagAuth        string
	flagRegion      string
	flagSSLRootCert string
)

func main() {
	root := &cobra.Command{
		Use:           "pgroledef",
		Short:         "Declarative, authoritative role management for Aurora PostgreSQL / Aurora DSQL",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetVersionTemplate(versionLine() + "\n")
	root.PersistentFlags().StringVarP(&flagFile, "file", "f", "", "jsonnet file to evaluate (required)")
	root.PersistentFlags().StringArrayVar(&flagExtStrs, "ext-str", nil, "external string variable KEY=VALUE (repeatable)")
	root.PersistentFlags().StringArrayVarP(&flagJPaths, "jpath", "J", nil, "additional jsonnet import path (repeatable)")

	render := &cobra.Command{
		Use:   "render",
		Short: "Evaluate jsonnet, validate, and print the normalized canonical JSON",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(cfg)
		},
	}
	validate := &cobra.Command{
		Use:   "validate",
		Short: "Evaluate jsonnet and validate without connecting to a database",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "OK: %d roles, %d grants, %d default privileges\n",
				len(cfg.Roles), len(cfg.FlatGrants()), len(cfg.FlatDefaultPrivileges()))
			return nil
		},
	}
	planCmd := &cobra.Command{
		Use:   "plan",
		Short: "Show the SQL needed to reconcile the database with the declaration",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, _, err := buildPlan(cmd.Context())
			if err != nil {
				return err
			}
			printPlan(cmd, p)
			if err := writePlanSQL(cmd, p); err != nil {
				return err
			}
			if !p.Empty() {
				os.Exit(2)
			}
			return nil
		},
	}
	var autoApprove, allowDestroy bool
	applyCmd := &cobra.Command{
		Use:   "apply",
		Short: "Execute the plan against the database",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, connector, err := buildPlan(cmd.Context())
			if err != nil {
				return err
			}
			printPlan(cmd, p)
			if p.Empty() {
				return nil
			}
			if p.NeedsAllowDestroy() && !allowDestroy {
				return fmt.Errorf("plan contains destructive statements (REVOKE/NOLOGIN); re-run with --allow-destroy to apply them")
			}
			if !autoApprove {
				fmt.Fprint(cmd.OutOrStdout(), "\nApply these statements? Only 'yes' is accepted: ")
				line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
				if strings.TrimSpace(line) != "yes" {
					return fmt.Errorf("aborted")
				}
			}
			fmt.Fprintln(cmd.OutOrStdout())
			if err := plan.Apply(cmd.Context(), p, connector, cmd.OutOrStdout()); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "\nApplied %d statement(s).\n", len(p.Statements))
			return nil
		},
	}
	planCmd.Flags().StringVarP(&flagOut, "out", "o", "", "also write the plan to this file as an executable SQL script")
	applyCmd.Flags().BoolVar(&autoApprove, "auto-approve", false, "skip the confirmation prompt")
	applyCmd.Flags().BoolVar(&allowDestroy, "allow-destroy", false, "allow REVOKE / NOLOGIN statements")
	for _, c := range []*cobra.Command{planCmd, applyCmd} {
		c.Flags().StringVar(&flagDSN, "dsn", os.Getenv("PGROLEDEF_DSN"), "PostgreSQL connection string (default $PGROLEDEF_DSN, then libpq PG* env vars)")
		c.Flags().StringVar(&flagAuth, "auth", "", "how to authenticate: password, rds-iam, dsql, dsql-admin (default: password on aurora-postgresql, dsql-admin on dsql)")
		c.Flags().StringVar(&flagRegion, "region", "", "AWS region for IAM token signing (default: the AWS SDK's resolved region)")
		c.Flags().StringVar(&flagSSLRootCert, "sslrootcert", "", "CA bundle for verify-full; Aurora needs the RDS bundle")
	}

	root.AddCommand(render, validate, planCmd, applyCmd, newVersionCmd())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func loadConfig() (*config.Config, error) {
	if flagFile == "" {
		return nil, fmt.Errorf("--file is required")
	}
	ext := map[string]string{}
	for _, kv := range flagExtStrs {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, fmt.Errorf("--ext-str %q must be KEY=VALUE", kv)
		}
		ext[k] = v
	}
	raw, err := jsonnetx.EvaluateFile(flagFile, jsonnetx.Options{ExtStrs: ext, JPaths: flagJPaths})
	if err != nil {
		return nil, err
	}
	cfg, err := config.Decode(raw)
	if err != nil {
		return nil, err
	}
	return config.Validate(cfg)
}

func buildPlan(ctx context.Context) (*plan.Plan, catalog.Connector, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, nil, err
	}
	connector, err := newConnector(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	p, err := plan.Build(ctx, cfg, connector)
	if err != nil {
		return nil, nil, err
	}
	return p, connector, nil
}

// newConnector picks the authentication mode. Aurora accepts a password, so it
// stays the default there; DSQL has no passwords at all, so it defaults to an
// admin token.
func newConnector(ctx context.Context, cfg *config.Config) (catalog.Connector, error) {
	mode := defaultAuthMode(cfg.Target.Engine)
	if flagAuth != "" {
		m, err := awsauth.ParseMode(flagAuth)
		if err != nil {
			return nil, err
		}
		mode = m
	}
	if !mode.UsesToken() {
		return catalog.NewDSNConnector(flagDSN)
	}
	return awsauth.NewConnector(ctx, awsauth.Options{
		DSN:         flagDSN,
		Mode:        mode,
		Region:      flagRegion,
		SSLRootCert: flagSSLRootCert,
	})
}

func defaultAuthMode(engine config.Engine) awsauth.Mode {
	if engine == config.EngineDSQL {
		return awsauth.ModeDSQLAdmin
	}
	return awsauth.ModePassword
}

func writePlanSQL(cmd *cobra.Command, p *plan.Plan) error {
	if flagOut == "" {
		return nil
	}
	f, err := os.Create(flagOut)
	if err != nil {
		return err
	}
	if err := plan.WriteSQL(p, f); err != nil {
		f.Close() //nolint:errcheck // the write error is the one worth reporting
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "\nWrote %d statement(s) to %s\n", len(p.Statements), flagOut)
	return nil
}

func printPlan(cmd *cobra.Command, p *plan.Plan) {
	out := cmd.OutOrStdout()
	if p.Empty() {
		fmt.Fprintln(out, "No changes. The database matches the declaration.")
		return
	}
	p.WriteDiff(out)
	if !p.Dialect.Atomic() {
		fmt.Fprintf(out, "Note: %s applies one statement per transaction, so a failure leaves\n"+
			"      the statements before it in place. Re-run to converge.\n\n", p.Dialect.Engine)
	}
	fmt.Fprintln(out, "SQL:")
	for _, db := range p.Databases() {
		label := db
		if label == "" {
			label = "cluster"
		}
		fmt.Fprintf(out, "  -- %s\n", label)
		for _, s := range p.Statements {
			if s.Database != db {
				continue
			}
			mark := "+"
			if s.Destructive {
				mark = "-"
			}
			fmt.Fprintf(out, "  %s %s;", mark, s.SQL)
			if s.Note != "" {
				fmt.Fprintf(out, "  -- %s", s.Note)
			}
			fmt.Fprintln(out)
		}
	}
	n, d := len(p.Statements), 0
	for _, s := range p.Statements {
		if s.Destructive {
			d++
		}
	}
	fmt.Fprintf(out, "\nPlan: %d statement(s), %d destructive.\n", n, d)
}

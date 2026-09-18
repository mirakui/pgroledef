// Command pgroledef manages PostgreSQL roles and privileges declaratively from jsonnet.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/spf13/cobra"

	"github.com/mirakui/pgroledef/internal/awsauth"
	"github.com/mirakui/pgroledef/internal/catalog"
	"github.com/mirakui/pgroledef/internal/config"
	"github.com/mirakui/pgroledef/internal/conninfo"
	"github.com/mirakui/pgroledef/internal/jsonnetx"
	"github.com/mirakui/pgroledef/internal/plan"
	"github.com/mirakui/pgroledef/internal/termcolor"
)

var (
	flagFile        string
	flagExtStrs     []string
	flagJPaths      []string
	flagDSN         string
	flagHost        string
	flagPort        string
	flagUser        string
	flagDBName      string
	flagPassword    bool
	flagNoPassword  bool
	flagOut         string
	flagAuth        string
	flagRegion      string
	flagSSLRootCert string
	flagNoColor     bool
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
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
			p, _, err := buildPlan(cmd)
			if err != nil {
				return err
			}
			printPlan(cmd.OutOrStdout(), palette(cmd.OutOrStdout()), p)
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
			p, connector, err := buildPlan(cmd)
			if err != nil {
				return err
			}
			printPlan(cmd.OutOrStdout(), palette(cmd.OutOrStdout()), p)
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
		c.Flags().BoolVar(&flagNoColor, "no-color", false, "disable coloured output (also honours NO_COLOR)")
		c.Flags().StringVarP(&flagHost, "host", "h", "", "database server host (default: the DSN, then $PGHOST)")
		c.Flags().StringVarP(&flagPort, "port", "p", "", "database server port (default: the DSN, then $PGPORT)")
		c.Flags().StringVarP(&flagUser, "username", "U", "", "database user name (default: the DSN, then $PGUSER)")
		c.Flags().StringVarP(&flagDBName, "dbname", "d", "", "database to connect to (default: the DSN, then $PGDATABASE)")
		c.Flags().BoolVarP(&flagPassword, "password", "W", false, "prompt for the password before connecting instead of waiting for the server to ask")
		c.Flags().BoolVarP(&flagNoPassword, "no-password", "w", false, "never prompt; fail with the server's error if a password is missing")
		c.MarkFlagsMutuallyExclusive("password", "no-password")
		// -h belongs to the host here, as it does in psql. Registering help
		// first stops cobra from claiming the shorthand for itself.
		c.Flags().Bool("help", false, "help for "+c.Name())
		// "plan -h" is otherwise reported as a missing argument, which reads
		// like a bug to anyone who expected the usage text.
		c.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
			if strings.Contains(err.Error(), "'h' in -h") {
				return fmt.Errorf("%w (-h is the server host here; use --help for usage)", err)
			}
			return err
		})
	}

	root.AddCommand(render, validate, planCmd, applyCmd, newVersionCmd())
	return root
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

func buildPlan(cmd *cobra.Command) (*plan.Plan, catalog.Connector, error) {
	ctx := cmd.Context()
	cfg, err := loadConfig()
	if err != nil {
		return nil, nil, err
	}
	connector, err := newConnector(cmd, cfg)
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
func newConnector(cmd *cobra.Command, cfg *config.Config) (catalog.Connector, error) {
	mode := defaultAuthMode(cfg.Target.Engine)
	if flagAuth != "" {
		m, err := awsauth.ParseMode(flagAuth)
		if err != nil {
			return nil, err
		}
		mode = m
	}
	co := conninfo.Options{
		DSN:      flagDSN,
		Host:     flagHost,
		Port:     flagPort,
		User:     flagUser,
		Database: flagDBName,
	}
	resolved, err := co.Resolve()
	if err != nil {
		return nil, err
	}
	if !mode.UsesToken() {
		return newDSNConnector(cmd, resolved.Conn)
	}
	if flagPassword {
		// Naming --auth would be misleading when the mode came from the
		// engine's default and the user never typed the flag.
		how := "--auth " + string(mode)
		if flagAuth == "" {
			how = fmt.Sprintf("the %s token mode, the default for engine %s", mode, cfg.Target.Engine)
		}
		return nil, fmt.Errorf("--password cannot be used with %s: a token is signed, never typed", how)
	}
	return awsauth.NewConnector(cmd.Context(), awsauth.Options{
		Resolved:    resolved,
		Mode:        mode,
		Region:      flagRegion,
		SSLRootCert: flagSSLRootCert,
	})
}

// newDSNConnector arranges for the password to be typed rather than put on the
// command line: --password asks up front, and otherwise the connector asks only
// if the server turns out to want one. Neither happens without a terminal, or
// with --no-password, so scripts keep failing with the server's own error.
func newDSNConnector(cmd *cobra.Command, connCfg *pgx.ConnConfig) (catalog.Connector, error) {
	c := catalog.NewConnConfigConnector(connCfg)
	if flagNoPassword {
		return c, nil
	}
	if !isTerminal(cmd.InOrStdin()) {
		if flagPassword {
			return nil, fmt.Errorf("--password needs a terminal to read from")
		}
		return c, nil
	}
	if flagPassword {
		password, err := promptPassword(cmd, c.Base.User)
		if err != nil {
			return nil, err
		}
		c.SetPassword(password)
		return c, nil
	}
	c.Prompt = passwordPrompter(cmd, c.Base.User)
	return c, nil
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

// printPlan writes the diff and the SQL that follows it. out and pal are
// passed in rather than taken from the command so the rendering can be tested
// on its own.
func printPlan(out io.Writer, pal *termcolor.Palette, p *plan.Plan) {
	if p.Empty() {
		fmt.Fprintln(out, pal.Bold("No changes. The database matches the declaration."))
		return
	}
	p.WriteDiff(out, pal)
	if !p.Dialect.Atomic() {
		fmt.Fprintf(out, "%s\n\n", pal.Change(fmt.Sprintf(
			"Note: %s applies one statement per transaction, so a failure leaves\n"+
				"      the statements before it in place. Re-run to converge.", p.Dialect.Engine)))
	}
	fmt.Fprintln(out, pal.Bold("SQL:"))
	for _, db := range p.Databases() {
		label := db
		if label == "" {
			label = "cluster"
		}
		fmt.Fprintf(out, "  %s\n", pal.Dim("-- "+label))
		for _, s := range p.Statements {
			if s.Database != db {
				continue
			}
			mark, style := "+", termcolor.Green
			if s.Destructive {
				mark, style = "-", termcolor.Red
			}
			fmt.Fprintf(out, "  %s", pal.Paint(fmt.Sprintf("%s %s;", mark, s.SQL), style))
			if s.Note != "" {
				fmt.Fprintf(out, "  %s", pal.Dim("-- "+s.Note))
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
	fmt.Fprintf(out, "\n%s\n", pal.Bold(fmt.Sprintf("Plan: %d statement(s), %d destructive.", n, d)))
}

// palette decides whether the plan output is coloured: --no-color always wins,
// otherwise colour follows the terminal.
func palette(out io.Writer) *termcolor.Palette {
	return termcolor.New(!flagNoColor && termcolor.Detect(out))
}

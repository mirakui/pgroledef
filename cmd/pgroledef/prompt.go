package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// isTerminal reports whether r is a terminal we can prompt on. Anything else —
// a pipe, a closed stdin, a CI runner — must fail with the server's own error
// rather than block waiting for input nobody can give.
func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// promptPassword reads a password from the terminal without echoing it. The
// prompt goes to stderr because plan output on stdout is routinely piped.
func promptPassword(cmd *cobra.Command, user string) (string, error) {
	f, ok := cmd.InOrStdin().(*os.File)
	if !ok {
		return "", fmt.Errorf("cannot read a password: stdin is not a terminal")
	}
	fd := int(f.Fd())
	state, err := term.GetState(fd)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	stop := restoreOnSignal(cmd, fd, state)
	defer stop()

	label := "Password: "
	if user != "" {
		label = fmt.Sprintf("Password for user %s: ", user)
	}
	fmt.Fprint(cmd.ErrOrStderr(), label)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(cmd.ErrOrStderr())
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return string(b), nil
}

// restoreOnSignal puts the terminal back before the process dies. Reading a
// password turns echo off but leaves SIGINT delivered, so a Ctrl-C at the
// prompt would otherwise kill us between the two and leave the operator's
// shell not echoing anything they type.
func restoreOnSignal(cmd *cobra.Command, fd int, state *term.State) func() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		select {
		case s := <-sig:
			_ = term.Restore(fd, state) // we are on our way out either way
			fmt.Fprintln(cmd.ErrOrStderr())
			code := 130
			if s == syscall.SIGTERM {
				code = 143
			}
			os.Exit(code)
		case <-done:
		}
	}()
	return func() {
		signal.Stop(sig)
		close(done)
	}
}

// passwordPrompter adapts promptPassword to catalog.PasswordPrompt.
func passwordPrompter(cmd *cobra.Command, user string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return promptPassword(cmd, user) }
}

// cabetool is a diagnostic CLI for working with a CABE deployment.
// See doc/2026-04-18-cabetool-design.md for the design overview.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/spf13/cobra"
)

// userAgent is the cabetool-specific prefix that is combined with
// ckapclient's default User-Agent on outgoing CKAP requests. The
// version comes from Go's build-info: for a binary built via `go
// install github.com/messier-42/cabe-go/cmd/cabetool@v1.2.3` the main
// module version is "v1.2.3"; for a local `go build` or `go run` it
// is "(devel)".
func userAgent() string {
	v := "(devel)"
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		v = bi.Main.Version
	}
	return "cabetool/" + v
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run is the testable main entry point. It executes the root command
// with the given argv (excluding argv[0]) and returns a process exit
// code. stdin / stdout / stderr redirection lets tests drive the CLI
// in-process without spawning a subprocess.
func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	root := newRootCommand() //nolint:contextcheck // cobra commands source ctx from cmd.Context() within RunE, not from run's ctx parameter
	root.SetArgs(args)
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)
	if err := root.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func newRootCommand() *cobra.Command {
	opts := &options{}

	root := &cobra.Command{
		Use:   "cabetool",
		Short: "Diagnostic CLI for CABE",
		Long: `cabetool is a stateless diagnostic command-line utility for
working with a CABE deployment. Top-level commands cover everyday
encap/decap/whoami flows; the "diag" subtree holds raw protocol and
inspection commands.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			applyEnv(cmd)
			logCfg, err := resolveLogConfig(cmd, opts)
			if err != nil {
				return err
			}
			slog.SetDefault(NewLogger(logCfg))
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			// With no subcommand specified, print help.
			return cmd.Help()
		},
	}

	registerGlobalFlags(root, opts)
	root.AddCommand(
		newWhoamiCommand(opts),
		newEncapCommand(opts),
		newDecapCommand(opts),
	)
	return root
}

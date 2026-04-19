package main

import (
	"fmt"

	"github.com/messier-42/cabe-go/cabecap"
	"github.com/spf13/cobra"
)

// decapMeta is the sidecar metadata written to --meta-out when
// decapsulating. The plaintext itself is written to --out so that
// --out defaulting to stdout keeps pipelines clean.
type decapMeta struct {
	AttributeSet map[string]any `json:"attributeSet"          yaml:"attributeSet"`
	ContentType  string         `json:"contentType,omitempty" yaml:"contentType,omitempty"`
}

func newDecapCommand(opts *options) *cobra.Command {
	var (
		inPath      string
		outPath     string
		metaOutPath string
	)
	cmd := &cobra.Command{
		Use:   "decap",
		Short: "Decapsulate a CBES envelope into a plaintext message",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			env, err := readInput(inPath, cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("read envelope: %w", err)
			}

			cfg, cleanup, err := makeClientConfig(cmd.Context(), opts)
			if err != nil {
				return err
			}
			defer cleanup()
			c, err := cabecap.NewWithClient(cfg, cabecap.WithARIN(false))
			if err != nil {
				return err
			}
			defer c.Close() // best effort

			msg, err := c.Decapsulate(cmd.Context(), env)
			if err != nil {
				return err
			}

			if err := writeOutput(outPath, msg.Payload, cmd.OutOrStdout()); err != nil {
				return fmt.Errorf("write plaintext: %w", err)
			}

			meta, err := openMetaOut(metaOutPath, cmd.ErrOrStderr())
			if err != nil {
				return fmt.Errorf("open --meta-out: %w", err)
			}
			defer meta.Close() // best effort
			return writeStructured(meta, decapMeta{
				AttributeSet: msg.Attributes.Map(),
				ContentType:  msg.ContentType,
			}, opts.JSON)
		},
	}
	cmd.Flags().StringVar(&inPath, "in", "", "envelope input path ('-' or empty = stdin)")
	cmd.Flags().StringVar(&outPath, "out", "", "plaintext output path ('-' or empty = stdout)")
	cmd.Flags().StringVar(&metaOutPath, "meta-out", "", `metadata destination ('-' or empty = stderr; "/dev/null" to suppress)`)
	return cmd
}

package main

import (
	"errors"
	"fmt"

	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/cabecap"
	"github.com/spf13/cobra"
)

func newEncapCommand(opts *options) *cobra.Command {
	var (
		attrs       []string
		inPath      string
		outPath     string
		contentType string
	)
	cmd := &cobra.Command{
		Use:   "encap",
		Short: "Encapsulate a plaintext message into a CBES envelope",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if len(attrs) == 0 {
				return errors.New("--attr is required at least once")
			}
			attrSet, err := buildAttributeSet(attrs)
			if err != nil {
				return err
			}

			payload, err := readInput(inPath, cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("read plaintext: %w", err)
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

			env, err := c.Encapsulate(cmd.Context(), cabe.Message{
				Payload:     payload,
				Attributes:  attrSet,
				ContentType: contentType,
			})
			if err != nil {
				return err
			}
			return writeOutput(outPath, env, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringArrayVarP(&attrs, "attr", "A", nil, "attribute spec KEY=TYPE:VALUE (TYPE in str|string|int|bool); repeatable")
	cmd.Flags().StringVar(&inPath, "in", "", "plaintext input path ('-' or empty = stdin)")
	cmd.Flags().StringVar(&outPath, "out", "", "envelope output path ('-' or empty = stdout)")
	cmd.Flags().StringVar(&contentType, "content-type", "application/octet-stream", "CBES envelope content-type header value")
	return cmd
}

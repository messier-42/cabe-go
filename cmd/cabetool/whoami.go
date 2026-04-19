package main

import (
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/ckap"
	"github.com/spf13/cobra"
)

// whoamiOutput is the structured payload written by `cabetool whoami`.
// The shape is deliberately flat and map-based so YAML and JSON
// produce comparable output.
type whoamiOutput struct {
	Principal  principalOutput `json:"principal"            yaml:"principal"`
	ServerInfo map[string]any  `json:"serverInfo,omitempty" yaml:"serverInfo,omitempty"`
}

type principalOutput struct {
	URI    string         `json:"uri"              yaml:"uri"`
	Claims map[string]any `json:"claims,omitempty" yaml:"claims,omitempty"`
}

func newWhoamiCommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Print the Key Server's view of the calling principal",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, cleanup, err := newClient(cmd.Context(), opts)
			if err != nil {
				return err
			}
			defer cleanup()
			defer client.Close() // best effort

			resp, err := client.GetSelf(cmd.Context(), ckap.GetSelfRequest{})
			if err != nil {
				return err
			}
			return writeStructured(cmd.OutOrStdout(), whoamiFromInfo(resp.PrincipalInfo), opts.JSON)
		},
	}
}

func whoamiFromInfo(p cabe.PrincipalInfo) whoamiOutput {
	return whoamiOutput{
		Principal: principalOutput{
			URI:    p.URI,
			Claims: p.Claims,
		},
		ServerInfo: p.ServerInfo,
	}
}

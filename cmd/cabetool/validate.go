package main

import (
	"errors"
	"fmt"

	"github.com/messier-42/cabe-go/acp240"
	"github.com/messier-42/cabe-go/attrset"
	"github.com/spf13/cobra"
)

func newValidateCommand(opts *options) *cobra.Command {
	var (
		attrs          []string
		inPath         string
		profileName    string
		structuralOnly bool
		defaultContext string
	)
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate an Attribute Set against an explicitly selected profile",
		Long: `Validate local attributes without contacting a Key Service or changing values.
Use -A as for encap, or --in for a deterministically encoded CBOR Attribute Set.
NATO and national policies require application-specific validation through the
acp240 API. --structural-only checks the published mapping rules without those checks.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if profileName != "acp240" {
				return errors.New("select --profile acp240")
			}
			hasInput := cmd.Flags().Changed("in")
			if hasInput == (len(attrs) != 0) {
				return errors.New("provide either --attr/-A or --in, but not both")
			}
			var set attrset.Set
			var err error
			if hasInput {
				var data []byte
				data, err = readInput(inPath, cmd.InOrStdin())
				if err == nil {
					set, err = attrset.NewFromBytes(data)
				}
			} else {
				set, err = buildAttributeSet(attrs)
			}
			if err != nil {
				return fmt.Errorf("read Attribute Set: %w", err)
			}
			profile := acp240.Profile{}
			if cmd.Flags().Changed("nato-default-context") {
				profile.DefaultNATOContext = []string{defaultContext}
			}
			scope := "full"
			if structuralOnly {
				scope = "structural-only"
				err = profile.ValidateStructure(set)
			} else {
				err = profile.Validate(set)
			}
			if errors.Is(err, acp240.ErrPolicyRequired) {
				return fmt.Errorf("%w; use the acp240 API for delegated policy checks, or --structural-only to check only the published mapping rules", err)
			}
			if err != nil {
				return err
			}
			return writeStructured(cmd.OutOrStdout(), map[string]any{
				"profile":      profileName,
				"scope":        scope,
				"attributeSet": set.Map(),
			}, opts.JSON)
		},
	}
	cmd.Flags().StringVar(&profileName, "profile", "", "attribute profile to validate (acp240)")
	cmd.Flags().StringArrayVarP(&attrs, "attr", "A", nil, "attribute spec KEY=TYPE:VALUE as for encap; repeatable")
	cmd.Flags().StringVar(&inPath, "in", "", "CBOR Attribute Set input path ('-' = stdin); exclusive with --attr")
	cmd.Flags().BoolVar(&structuralOnly, "structural-only", false, "check explicit mapping rules, including NATO/PUBLIC constraints, without delegated policy checks")
	cmd.Flags().StringVar(&defaultContext, "nato-default-context", "", "explicit canonical compatibility context for an existing NATO Set with no c")
	return cmd
}

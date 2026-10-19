package acp240_test

import (
	"errors"
	"fmt"

	"github.com/messier-42/cabe-go/acp240"
	"github.com/messier-42/cabe-go/attrset"
)

func ExampleNew() {
	set, err := acp240.New(acp240.Attributes{
		PolicyIdentifier: "public",
		Sensitivity:      "unmarked",
		Releasability:    []string{"usa", "fvey", "can"},
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(set.Map())
	fmt.Println((acp240.Profile{}).Validate(set))
	decoded, err := attrset.NewFromBytes([]byte(set.Repr()))
	if err != nil {
		panic(err)
	}
	fmt.Println(decoded.Repr() == set.Repr())
	// Output:
	// map[p:PUBLIC r:CAN,FVEY,USA s:UNMARKED]
	// <nil>
	// true
}

func ExampleProfile_Validate() {
	// This demonstrates insufficient policy information, not national policy.
	set, err := acp240.New(acp240.Attributes{
		PolicyIdentifier: "USA",
		Sensitivity:      "SECRET",
	})
	if err != nil {
		panic(err)
	}
	profile := acp240.Profile{}
	fmt.Println(profile.ValidateStructure(set))
	fmt.Println(errors.Is(profile.Validate(set), acp240.ErrPolicyRequired))
	// Output:
	// <nil>
	// true
}

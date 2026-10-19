package acp240_test

import (
	"fmt"

	"github.com/messier-42/cabe-go/acp240"
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
	// Output:
	// map[p:PUBLIC r:CAN,FVEY,USA s:UNMARKED]
}

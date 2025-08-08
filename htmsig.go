package htmsig

import "github.com/lestrrat-go/htmsig/internal/common"

const (
	SignatureInputHeader = "Signature-Input"
	SignatureHeader      = "Signature"
)

type Component = common.Component

var (
	methodComponent = common.NewComponent("@method")
)

func MethodComponent() Component {
	return methodComponent
}

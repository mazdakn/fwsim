package engine

import (
	"fmt"
	"net"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/mazdakn/fwsim/internal/model"
)

// CEL expressions used to validate firewall configuration values.
// Both expressions delegate to a custom function; the functions encapsulate the
// domain-specific parsing logic so that error reporting is left to the caller.
const (
	// validCIDRExpr evaluates to true if 'value' is valid CIDR notation.
	validCIDRExpr = `isValidCIDR(value)`
	// validActionExpr evaluates to true if 'value' is a recognised action string.
	// Empty strings are implicitly rejected because isValidAction("") returns false.
	validActionExpr = `isValidAction(value)`
)

// configValidator holds pre-compiled CEL programs for validating firewall config values.
type configValidator struct {
	cidrPrg   cel.Program
	actionPrg cel.Program
}

// validatorOnce guards the package-level singleton so CEL programs are compiled only once.
var (
	validatorOnce sync.Once
	sharedValidator     *configValidator
	sharedValidatorErr  error
)

// getValidator returns the package-level singleton configValidator, initialising it on the
// first call. CEL program compilation is deterministic and the expressions are constants,
// so a single shared instance is safe for concurrent use.
func getValidator() (*configValidator, error) {
	validatorOnce.Do(func() {
		sharedValidator, sharedValidatorErr = newConfigValidator()
	})
	return sharedValidator, sharedValidatorErr
}

// newConfigValidator creates a CEL environment with custom isValidCIDR and isValidAction
// functions, compiles the validation expressions, and returns a ready-to-use validator.
func newConfigValidator() (*configValidator, error) {
	env, err := cel.NewEnv(
		cel.Variable("value", cel.StringType),
		cel.Function("isValidCIDR",
			cel.Overload("isValidCIDR_string",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					cidr, ok := val.Value().(string)
					if !ok {
						return types.Bool(false)
					}
					_, _, err := net.ParseCIDR(cidr)
					return types.Bool(err == nil)
				}),
			),
		),
		cel.Function("isValidAction",
			cel.Overload("isValidAction_string",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					s, ok := val.Value().(string)
					if !ok {
						return types.Bool(false)
					}
					_, err := model.ParseAction(s)
					return types.Bool(err == nil)
				}),
			),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	cidrAst, iss := env.Compile(validCIDRExpr)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("failed to compile CIDR validation expression: %w", iss.Err())
	}
	cidrPrg, err := env.Program(cidrAst)
	if err != nil {
		return nil, fmt.Errorf("failed to create CIDR validation program: %w", err)
	}

	actionAst, iss := env.Compile(validActionExpr)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("failed to compile action validation expression: %w", iss.Err())
	}
	actionPrg, err := env.Program(actionAst)
	if err != nil {
		return nil, fmt.Errorf("failed to create action validation program: %w", err)
	}

	return &configValidator{
		cidrPrg:   cidrPrg,
		actionPrg: actionPrg,
	}, nil
}

// validateCIDR returns true if cidr is valid CIDR notation.
func (v *configValidator) validateCIDR(cidr string) bool {
	out, _, err := v.cidrPrg.Eval(map[string]any{"value": cidr})
	if err != nil {
		return false
	}
	return out == types.True
}

// validateAction returns true if action is a non-empty, recognised action string.
func (v *configValidator) validateAction(action string) bool {
	out, _, err := v.actionPrg.Eval(map[string]any{"value": action})
	if err != nil {
		return false
	}
	return out == types.True
}

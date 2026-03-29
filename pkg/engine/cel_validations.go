package engine

import (
	"fmt"
	"net"
	"reflect"
	"strings"
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
	// validIPExpr evaluates to true if 'value' is a valid IP address.
	validIPExpr = `isValidIP(value)`
)

// configValidator holds pre-compiled CEL programs for validating firewall config values.
type configValidator struct {
	cidrPrg   cel.Program
	actionPrg cel.Program
	ipPrg     cel.Program
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

// newConfigValidator creates a CEL environment with custom isValidCIDR, isValidAction,
// and isValidIP functions, compiles the validation expressions, and returns a
// ready-to-use validator.
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
		cel.Function("isValidIP",
			cel.Overload("isValidIP_string",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					s, ok := val.Value().(string)
					if !ok {
						return types.Bool(false)
					}
					return types.Bool(net.ParseIP(s) != nil)
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

	ipAst, iss := env.Compile(validIPExpr)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("failed to compile IP validation expression: %w", iss.Err())
	}
	ipPrg, err := env.Program(ipAst)
	if err != nil {
		return nil, fmt.Errorf("failed to create IP validation program: %w", err)
	}

	return &configValidator{
		cidrPrg:   cidrPrg,
		actionPrg: actionPrg,
		ipPrg:     ipPrg,
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

// validateIP returns true if ip is a valid IP address.
func (v *configValidator) validateIP(ip string) bool {
	out, _, err := v.ipPrg.Eval(map[string]any{"value": ip})
	if err != nil {
		return false
	}
	return out == types.True
}

// validateByTag validates value using the CEL function identified by tag.
// It returns an error if tag is not a recognised CEL function name, so that
// a typo in a struct tag is surfaced immediately rather than silently failing.
func (v *configValidator) validateByTag(tag, value string) (bool, error) {
	switch tag {
	case "isValidCIDR":
		return v.validateCIDR(value), nil
	case "isValidAction":
		return v.validateAction(value), nil
	case "isValidIP":
		return v.validateIP(value), nil
	default:
		return false, fmt.Errorf("unknown CEL validation tag: %s", tag)
	}
}

// validateStructFields validates all string and []string fields in s that carry a
// "cel" struct tag. The tag value must be a CEL function name recognised by
// validateByTag. Field names used in error messages are taken from the "yaml" tag.
//
// Validation semantics:
//   - string fields: empty values are skipped (field is treated as optional).
//   - []string fields: every element is validated, including empty strings, because
//     an empty string in a list (e.g. a CIDR slice) is never a valid value.
func (v *configValidator) validateStructFields(s any) error {
	t := reflect.TypeOf(s)
	val := reflect.ValueOf(s)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
		val = val.Elem()
	}

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		celTag := field.Tag.Get("cel")
		if celTag == "" {
			continue
		}

		yamlTag := field.Tag.Get("yaml")
		fieldName := strings.Split(yamlTag, ",")[0]
		if fieldName == "" || fieldName == "-" {
			fieldName = field.Name
		}

		fieldVal := val.Field(i)
		switch field.Type.Kind() {
		case reflect.String:
			str := fieldVal.String()
			if str == "" {
				continue
			}
			ok, err := v.validateByTag(celTag, str)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("invalid %s %s", fieldName, str)
			}
		case reflect.Slice:
			if field.Type.Elem().Kind() == reflect.String {
				for j := 0; j < fieldVal.Len(); j++ {
					str := fieldVal.Index(j).String()
					ok, err := v.validateByTag(celTag, str)
					if err != nil {
						return err
					}
					if !ok {
						return fmt.Errorf("invalid %s %s", fieldName, str)
					}
				}
			}
		}
	}
	return nil
}

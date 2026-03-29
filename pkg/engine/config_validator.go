package engine

import (
	"fmt"
	"net"
	"reflect"
	"strings"

	"github.com/mazdakn/fwsim/internal"
)

// configValidator validates firewall configuration values using native Go functions.
type configValidator struct{}

// newConfigValidator returns a configValidator ready for use.
func newConfigValidator() (*configValidator, error) {
	return &configValidator{}, nil
}

// validateCIDR returns true if cidr is valid CIDR notation.
func (v *configValidator) validateCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

// validateAction returns true if action is a non-empty, recognised action string.
func (v *configValidator) validateAction(action string) bool {
	_, err := model.ParseAction(action)
	return err == nil
}

// validateIP returns true if ip is a valid IP address.
func (v *configValidator) validateIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// validateByTag validates value using the function identified by tag.
// It returns an error if tag is not a recognised function name, so that
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
		return false, fmt.Errorf("unknown validation tag: %s", tag)
	}
}

// validateStructFields validates all string and []string fields in s that carry a
// "validate" struct tag. The tag value must be a function name recognised by
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
		validateTag := field.Tag.Get("validate")
		if validateTag == "" {
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
			ok, err := v.validateByTag(validateTag, str)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("invalid %s: %s", fieldName, str)
			}
		case reflect.Slice:
			if field.Type.Elem().Kind() == reflect.String {
				for j := 0; j < fieldVal.Len(); j++ {
					str := fieldVal.Index(j).String()
					ok, err := v.validateByTag(validateTag, str)
					if err != nil {
						return err
					}
					if !ok {
						return fmt.Errorf("invalid %s: %s", fieldName, str)
					}
				}
			}
		}
	}
	return nil
}

package validator

import (
	"fmt"
	"net"
	"reflect"
	"strings"

	"github.com/mazdakn/fwsim/internal/rule"
)

// ValidateCIDR returns true if cidr is valid CIDR notation.
func ValidateCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

// ValidateAction returns true if action is a non-empty, recognised action string.
func ValidateAction(action string) bool {
	_, err := rule.ParseAction(action)
	return err == nil
}

// ValidateIP returns true if ip is a valid IP address.
func ValidateIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// validateByTag validates value using the function identified by tag.
// It returns an error if tag is not a recognised function name, so that
// a typo in a struct tag is surfaced immediately rather than silently failing.
func validateByTag(tag, value string) (bool, error) {
	switch tag {
	case "isValidCIDR":
		return ValidateCIDR(value), nil
	case "isValidAction":
		return ValidateAction(value), nil
	case "isValidIP":
		return ValidateIP(value), nil
	default:
		return false, fmt.Errorf("unknown validation tag: %s", tag)
	}
}

// ValidateStructFields validates all fields in s that carry a "validate" struct
// tag, as well as any slice-of-struct fields (validated recursively). The tag
// value must be a function name recognised by validateByTag. Field names used
// in error messages are taken from the "yaml" tag.
//
// Validation semantics:
//   - string fields: every value is validated, including empty strings; the
//     validator function decides whether an empty string is acceptable.
//   - []string fields: every element is validated, including empty strings, because
//     an empty string in a list (e.g. a CIDR slice) is never a valid value.
//   - []struct (or []*struct) fields: ValidateStructFields is called recursively
//     on each element regardless of whether the field carries a validate tag.
func ValidateStructFields(s any) error {
	t := reflect.TypeOf(s)
	val := reflect.ValueOf(s)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
		val = val.Elem()
	}

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldVal := val.Field(i)

		yamlTag := field.Tag.Get("yaml")
		fieldName := strings.Split(yamlTag, ",")[0]
		if fieldName == "" || fieldName == "-" {
			fieldName = field.Name
		}

		// Recursively validate slice-of-struct fields without requiring a tag.
		if field.Type.Kind() == reflect.Slice {
			elemType := field.Type.Elem()
			isPtr := elemType.Kind() == reflect.Ptr
			if isPtr {
				elemType = elemType.Elem()
			}
			if elemType.Kind() == reflect.Struct {
				for j := 0; j < fieldVal.Len(); j++ {
					elem := fieldVal.Index(j)
					if isPtr && elem.IsNil() {
						continue
					}
					if err := ValidateStructFields(elem.Interface()); err != nil {
						return fmt.Errorf("%s[%d]: %w", fieldName, j, err)
					}
				}
				continue
			}
		}

		validateTag := field.Tag.Get("validate")
		if validateTag == "" {
			continue
		}

		switch field.Type.Kind() {
		case reflect.String:
			str := fieldVal.String()
			ok, err := validateByTag(validateTag, str)
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
					ok, err := validateByTag(validateTag, str)
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

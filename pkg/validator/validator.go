package validator

import (
	"fmt"
	"net"
	"reflect"
	"strings"

	"github.com/mazdakn/fwsim/pkg/port"
	"github.com/mazdakn/fwsim/pkg/rule"
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

// ValidatePort returns true if port is a valid port number (0–65535).
func ValidatePort(port uint) bool {
	return port <= 65535
}

// ValidatePortValue returns true if p is a valid port: numeric ports are always
// valid (uint16 guarantees range 0–65535), and named ports must be a well-known
// service name recognised by port.Parse.
func ValidatePortValue(p port.Port) bool {
	if p.Name == "" {
		return true
	}
	_, err := port.Parse(p.Name)
	return err == nil
}

// ValidateProtocol returns true if proto is a valid IP protocol number (0–255).
func ValidateProtocol(proto uint) bool {
	return proto <= 255
}

// ValidateSetType returns true if setType is a recognised set type ("ip", "port", "proto").
func ValidateSetType(setType string) bool {
	switch setType {
	case "ip", "port", "proto":
		return true
	default:
		return false
	}
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
	case "isValidSetType":
		return ValidateSetType(value), nil
	default:
		return false, fmt.Errorf("unknown validation tag: %s", tag)
	}
}

// validateUintByTag validates a uint value using the function identified by tag.
// It returns an error if tag is not a recognised function name.
func validateUintByTag(tag string, value uint64) (bool, error) {
	switch tag {
	case "isPortValid":
		return value <= 65535, nil
	case "isProtoValid":
		return value <= 255, nil
	default:
		return false, fmt.Errorf("unknown validation tag: %s", tag)
	}
}

// validateStructByTag validates a struct value using the function identified by
// tag. It returns an error if tag is not a recognised function name for struct
// types.
func validateStructByTag(tag string, fieldVal reflect.Value) (bool, error) {
	switch tag {
	case "isPortValid":
		p, ok := fieldVal.Interface().(port.Port)
		if !ok {
			return false, fmt.Errorf("isPortValid: expected port.Port, got %T", fieldVal.Interface())
		}
		return ValidatePortValue(p), nil
	default:
		return false, fmt.Errorf("unknown validation tag for struct: %s", tag)
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

		// Validate or recursively validate named struct fields.
		// If the field carries a validate tag, validate the struct as a whole
		// using that tag. Otherwise recurse into its fields.
		if field.Type.Kind() == reflect.Struct {
			validateTag := field.Tag.Get("validate")
			if validateTag != "" {
				ok, err := validateStructByTag(validateTag, fieldVal)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("invalid %s: %v", fieldName, fieldVal.Interface())
				}
			} else {
				if err := ValidateStructFields(fieldVal.Interface()); err != nil {
					return fmt.Errorf("%s: %w", fieldName, err)
				}
			}
			continue
		}

		// Validate or recursively validate slice-of-struct fields.
		// If the field carries a validate tag, validate each element as a whole
		// using that tag. Otherwise recurse into each element's fields.
		if field.Type.Kind() == reflect.Slice {
			elemType := field.Type.Elem()
			isPtr := elemType.Kind() == reflect.Ptr
			if isPtr {
				elemType = elemType.Elem()
			}
			if elemType.Kind() == reflect.Struct {
				validateTag := field.Tag.Get("validate")
				for j := 0; j < fieldVal.Len(); j++ {
					elem := fieldVal.Index(j)
					if isPtr && elem.IsNil() {
						continue
					}
					if validateTag != "" {
						ok, err := validateStructByTag(validateTag, elem)
						if err != nil {
							return err
						}
						if !ok {
							return fmt.Errorf("invalid %s[%d]: %v", fieldName, j, elem.Interface())
						}
					} else {
						if err := ValidateStructFields(elem.Interface()); err != nil {
							return fmt.Errorf("%s[%d]: %w", fieldName, j, err)
						}
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
		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uint:
			v := fieldVal.Uint()
			ok, err := validateUintByTag(validateTag, v)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("invalid %s: %d", fieldName, v)
			}
		case reflect.Slice:
			switch field.Type.Elem().Kind() {
			case reflect.String:
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
			case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uint:
				for j := 0; j < fieldVal.Len(); j++ {
					v := fieldVal.Index(j).Uint()
					ok, err := validateUintByTag(validateTag, v)
					if err != nil {
						return err
					}
					if !ok {
						return fmt.Errorf("invalid %s: %d", fieldName, v)
					}
				}
			}
		}
	}
	return nil
}

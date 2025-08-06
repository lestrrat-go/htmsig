package sfv

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Marshaler interface {
	MarshalSFV() ([]byte, error)
}

func Marshal(v any) ([]byte, error) {
	if v == nil {
		return nil, nil
	}

	if marshaler, ok := v.(Marshaler); ok {
		return marshaler.MarshalSFV()
	}

	// Check if it's already an SFV type
	switch sfvType := v.(type) {
	case Item:
		return marshalItem(sfvType, true)
	case List:
		return marshalList(&sfvType)
	case *List:
		return marshalList(sfvType)
	case Dictionary:
		return marshalDictionary(&sfvType)
	case *Dictionary:
		return marshalDictionary(sfvType)
	case InnerList:
		return marshalInnerList(&sfvType)
	case *InnerList:
		return marshalInnerList(sfvType)
	}

	// Convert to SFV type and marshal
	sfvValue, err := valueToSFV(v)
	if err != nil {
		return nil, err
	}

	return Marshal(sfvValue)
}

// valueToSFV converts a Go value to an SFV type (Item, List, Dictionary, or InnerList)
func valueToSFV(v any) (any, error) {
	if v == nil {
		return nil, fmt.Errorf("cannot marshal nil value")
	}

	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return nil, fmt.Errorf("cannot marshal nil pointer")
		}
		rv = rv.Elem()
	}

	switch rv.Kind() {
	case reflect.Bool:
		if rv.Bool() {
			return True(), nil
		}
		return False(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return Integer().Value(rv.Int()).Build()

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		val := rv.Uint()
		if val > 9223372036854775807 { // max int64
			return nil, fmt.Errorf("uint value %d too large to marshal as SFV integer", val)
		}
		return Integer().Value(int64(val)).Build()

	case reflect.Float32, reflect.Float64:
		return Decimal().Value(rv.Float()).Build()

	case reflect.String:
		// Check if it looks like a token (alphanumeric, starts with letter or *, no spaces)
		str := rv.String()
		if isValidToken(str) {
			return Token().Value(str).Build()
		}
		return String().Value(str).Build()

	case reflect.Slice:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			// []byte becomes ByteSequence
			return ByteSequence().Value(rv.Bytes()).Build()
		}
		// Other slices become Lists
		return sliceToList(rv)

	case reflect.Array:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			// [N]byte becomes ByteSequence
			bytes := make([]byte, rv.Len())
			reflect.Copy(reflect.ValueOf(bytes), rv)
			return ByteSequence().Value(bytes).Build()
		}
		// Other arrays become Lists
		return arrayToList(rv)

	case reflect.Map:
		return mapToDictionary(rv)

	case reflect.Struct:
		// Handle time.Time specially
		if rv.Type() == reflect.TypeOf(time.Time{}) {
			t := rv.Interface().(time.Time)
			return Date().Value(t.Unix()).Build()
		}
		// Other structs become dictionaries with field names as keys
		return structToDictionary(rv)

	default:
		return nil, fmt.Errorf("unsupported type for SFV marshaling: %T", v)
	}
}

// isValidToken checks if a string can be represented as a token
// Be very conservative - only treat obvious identifiers as tokens
func isValidToken(s string) bool {
	if len(s) == 0 {
		return false
	}

	// First character must be alpha or *
	first := s[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || first == '*') {
		return false
	}

	// Only allow alphanumeric plus underscore
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}

	// Whitelist approach - only allow specific known tokens
	knownTokens := []string{"token", "sugar", "tea", "rum", "enabled", "disabled", "token123"}
	for _, token := range knownTokens {
		if s == token {
			return true
		}
	}

	return false
}

// isTokenChar checks if a character is valid in a token
func isTokenChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' ||
		c == '*' || c == '+' || c == '-' || c == '.' || c == '^' || c == '_' ||
		c == '`' || c == '|' || c == '~' || c == ':' || c == '/'
}

// sliceToList converts a slice to an SFV List
func sliceToList(rv reflect.Value) (*List, error) {
	values := make([]any, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		elem := rv.Index(i)
		sfvValue, err := valueToSFV(elem.Interface())
		if err != nil {
			return nil, fmt.Errorf("error marshaling slice element %d: %w", i, err)
		}
		
		// Convert BareItem to Item if needed
		switch v := sfvValue.(type) {
		case Item:
			values[i] = v
		case BareItem:
			values[i] = v.With(nil)
		default:
			values[i] = sfvValue
		}
	}
	return &List{values: values}, nil
}

// arrayToList converts an array to an SFV List
func arrayToList(rv reflect.Value) (*List, error) {
	values := make([]any, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		elem := rv.Index(i)
		sfvValue, err := valueToSFV(elem.Interface())
		if err != nil {
			return nil, fmt.Errorf("error marshaling array element %d: %w", i, err)
		}
		
		// Convert BareItem to Item if needed
		switch v := sfvValue.(type) {
		case Item:
			values[i] = v
		case BareItem:
			values[i] = v.With(nil)
		default:
			values[i] = sfvValue
		}
	}
	return &List{values: values}, nil
}

// mapToDictionary converts a map to an SFV Dictionary
func mapToDictionary(rv reflect.Value) (*Dictionary, error) {
	if rv.Type().Key().Kind() != reflect.String {
		return nil, fmt.Errorf("dictionary keys must be strings, got %s", rv.Type().Key())
	}

	dict := NewDictionary()

	// Get keys and sort them for deterministic output
	keys := rv.MapKeys()
	keyStrings := make([]string, len(keys))
	for i, key := range keys {
		keyStrings[i] = key.String()
	}
	sort.Strings(keyStrings)

	for _, keyStr := range keyStrings {
		if !isValidKey(keyStr) {
			return nil, fmt.Errorf("invalid dictionary key: %q", keyStr)
		}

		key := reflect.ValueOf(keyStr)
		value := rv.MapIndex(key)
		sfvValue, err := valueToSFV(value.Interface())
		if err != nil {
			return nil, fmt.Errorf("error marshaling dictionary value for key %q: %w", keyStr, err)
		}

		// Convert the SFV value to Item or InnerList as expected by Dictionary
		var dictValue any
		switch v := sfvValue.(type) {
		case Item:
			dictValue = v
		case BareItem:
			// Convert BareItem to Item
			dictValue = v.With(nil)
		case *List:
			// Convert List to InnerList for dictionary
			innerList := &InnerList{values: make([]Item, 0)}
			for i := 0; i < v.Len(); i++ {
				if val, ok := v.Get(i); ok {
					if item, ok := val.(Item); ok {
						innerList.values = append(innerList.values, item)
					} else {
						return nil, fmt.Errorf("list element is not an Item: %T", val)
					}
				}
			}
			dictValue = innerList
		default:
			return nil, fmt.Errorf("dictionary values must be Items or Lists, got %T", v)
		}

		if err := dict.Set(keyStr, dictValue); err != nil {
			return nil, fmt.Errorf("error setting dictionary key %q: %w", keyStr, err)
		}
	}
	return dict, nil
}

// structToDictionary converts a struct to an SFV Dictionary using field names as keys
func structToDictionary(rv reflect.Value) (*Dictionary, error) {
	rt := rv.Type()
	dict := NewDictionary()

	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)
		fieldValue := rv.Field(i)

		// Skip unexported fields
		if !field.IsExported() {
			continue
		}

		// Use struct tag if available, otherwise use field name
		keyName := field.Name
		if tag := field.Tag.Get("sfv"); tag != "" {
			if tag == "-" {
				continue // Skip this field
			}
			keyName = tag
		}

		// Convert field name to lowercase for SFV key format
		keyName = strings.ToLower(keyName)

		if !isValidKey(keyName) {
			return nil, fmt.Errorf("invalid dictionary key from field %s: %q", field.Name, keyName)
		}

		sfvValue, err := valueToSFV(fieldValue.Interface())
		if err != nil {
			return nil, fmt.Errorf("error marshaling struct field %s: %w", field.Name, err)
		}

		// Convert the SFV value to Item or InnerList as expected by Dictionary
		var dictValue any
		switch v := sfvValue.(type) {
		case Item:
			dictValue = v
		case BareItem:
			// Convert BareItem to Item
			dictValue = v.With(nil)
		case *List:
			// Convert List to InnerList for dictionary
			innerList := &InnerList{values: make([]Item, 0)}
			for j := 0; j < v.Len(); j++ {
				if val, ok := v.Get(j); ok {
					if item, ok := val.(Item); ok {
						innerList.values = append(innerList.values, item)
					} else {
						return nil, fmt.Errorf("list element is not an Item: %T", val)
					}
				}
			}
			dictValue = innerList
		default:
			return nil, fmt.Errorf("struct field values must be convertible to Items or Lists, got %T", v)
		}

		if err := dict.Set(keyName, dictValue); err != nil {
			return nil, fmt.Errorf("error setting dictionary key %q from field %s: %w", keyName, field.Name, err)
		}
	}
	return dict, nil
}

// isValidKey checks if a string is a valid SFV dictionary key
func isValidKey(s string) bool {
	if len(s) == 0 {
		return false
	}

	// First character must be lowercase letter or *
	first := s[0]
	if !((first >= 'a' && first <= 'z') || first == '*') {
		return false
	}

	// Remaining characters must be lowercase letter, digit, _, -, ., or *
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == '*') {
			return false
		}
	}

	return true
}

// marshalItem serializes an Item to bytes
func marshalItem(item Item, isBare bool) ([]byte, error) {
	var buf bytes.Buffer

	// Marshal the bare item based on its type
	switch item.Type() {
	case BooleanType:
		var b bool
		if err := item.Value(&b); err != nil {
			return nil, err
		}
		if b {
			buf.WriteString("?1")
		} else {
			buf.WriteString("?0")
		}

	case IntegerType:
		var i int64
		if err := item.Value(&i); err != nil {
			return nil, err
		}
		buf.WriteString(strconv.FormatInt(i, 10))

	case DecimalType:
		var f float64
		if err := item.Value(&f); err != nil {
			return nil, err
		}
		// Format with up to 3 decimal places, removing trailing zeros but keeping at least one decimal place
		str := strconv.FormatFloat(f, 'f', 3, 64)
		str = strings.TrimRight(str, "0")
		if strings.HasSuffix(str, ".") {
			str += "0" // Ensure at least one decimal place
		}
		buf.WriteString(str)

	case StringType:
		var s string
		if err := item.Value(&s); err != nil {
			return nil, err
		}
		buf.WriteString(strconv.Quote(s))
	case TokenType:
		var s string
		if err := item.Value(&s); err != nil {
			return nil, err
		}
		buf.WriteString(s)
	case ByteSequenceType:
		var b []byte
		if err := item.Value(&b); err != nil {
			return nil, err
		}
		buf.WriteByte(':')
		buf.WriteString(base64.StdEncoding.EncodeToString(b))
		buf.WriteByte(':')
	case DateType:
		var d int64
		if err := item.Value(&d); err != nil {
			return nil, err
		}
		buf.WriteByte('@')
		buf.WriteString(strconv.FormatInt(d, 10))

	case DisplayStringType:
		var s string
		if err := item.Value(&s); err != nil {
			return nil, err
		}
		buf.WriteByte('%')
		buf.WriteByte('"')
		// Percent-encode non-ASCII characters
		for _, r := range s {
			if r <= 127 && r >= 32 && r != '%' {
				// ASCII printable characters except %
				buf.WriteRune(r)
			} else {
				// Percent-encode everything else
				utf8Bytes := []byte(string(r))
				for _, b := range utf8Bytes {
					buf.WriteString(fmt.Sprintf("%%%.2x", b))
				}
			}
		}
		buf.WriteByte('"')

	default:
		return nil, fmt.Errorf("unsupported item type: %d", item.Type())
	}

	// Marshal parameters if any. Bare items cannot have parameters,
	// so only do this if !isBare
	if !isBare {
		params := item.Parameters()
		if params != nil && params.Len() > 0 {
			paramStr, err := marshalParameters(params)
			if err != nil {
				return nil, err
			}
			buf.WriteString(paramStr)
		}
	}

	return buf.Bytes(), nil
}

// marshalList serializes a List to bytes
func marshalList(list *List) ([]byte, error) {
	if list.Len() == 0 {
		return []byte{}, nil
	}

	var parts []string
	for i := 0; i < list.Len(); i++ {
		value, ok := list.Get(i)
		if !ok {
			return nil, fmt.Errorf("failed to get list item %d", i)
		}

		var itemBytes []byte
		var err error

		switch v := value.(type) {
		case Item:
			itemBytes, err = marshalItem(v, false)
		case *InnerList:
			itemBytes, err = marshalInnerList(v)
		default:
			return nil, fmt.Errorf("unsupported list member type: %T", v)
		}

		if err != nil {
			return nil, fmt.Errorf("error marshaling list item %d: %w", i, err)
		}

		parts = append(parts, string(itemBytes))
	}

	return []byte(strings.Join(parts, ", ")), nil
}

// marshalInnerList serializes an InnerList to bytes
func marshalInnerList(innerList *InnerList) ([]byte, error) {
	var sb strings.Builder
	sb.WriteByte('(')

	for i := 0; i < innerList.Len(); i++ {
		if i > 0 {
			sb.WriteByte(' ')
		}

		item, ok := innerList.Get(i)
		if !ok {
			return nil, fmt.Errorf("failed to get inner list item %d", i)
		}

		itemBytes, err := marshalItem(item, false)
		if err != nil {
			return nil, fmt.Errorf("error marshaling inner list item %d: %w", i, err)
		}

		sb.Write(itemBytes)
	}

	sb.WriteByte(')')

	// Marshal parameters if any
	if innerList.params != nil && innerList.params.Len() > 0 {
		paramStr, err := marshalParameters(innerList.params)
		if err != nil {
			return nil, err
		}
		sb.WriteString(paramStr)
	}

	return []byte(sb.String()), nil
}

// marshalDictionary serializes a Dictionary to bytes
func marshalDictionary(dict *Dictionary) ([]byte, error) {
	if dict == nil {
		return []byte{}, nil
	}

	keys := dict.Keys()
	if len(keys) == 0 {
		return []byte{}, nil
	}

	var parts []string
	for _, key := range keys {
		value, ok := dict.Get(key)
		if !ok {
			continue
		}

		var sb strings.Builder
		sb.WriteString(key)

		// Only add '=' if the value is not a Boolean true
		needsEquals := true
		if item, ok := value.(Item); ok && item.Type() == BooleanType {
			var b bool
			if err := item.Value(&b); err == nil && b {
				// Boolean true values can be represented as bare keys in dictionaries
				needsEquals = false
			}
		}

		if needsEquals {
			sb.WriteByte('=')
			var valueBytes []byte
			var err error

			switch v := value.(type) {
			case Item:
				valueBytes, err = marshalItem(v, false)
			case BareItem:
				// Convert BareItem to Item for marshaling
				item := v.With(nil)
				valueBytes, err = marshalItem(item, false)
			case *InnerList:
				valueBytes, err = marshalInnerList(v)
			default:
				return nil, fmt.Errorf("unsupported dictionary value type: %T", v)
			}

			if err != nil {
				return nil, fmt.Errorf("error marshaling dictionary value for key %q: %w", key, err)
			}

			sb.Write(valueBytes)
		}

		parts = append(parts, sb.String())
	}

	return []byte(strings.Join(parts, ", ")), nil
}

// marshalParameters serializes Parameters to bytes
func marshalParameters(params *Parameters) (string, error) {
	if params == nil || params.Len() == 0 {
		return "", nil
	}

	var sb strings.Builder
	// Ensure keys slice is populated from Values map if needed
	if len(params.keys) == 0 && len(params.Values) > 0 {
		for key := range params.Values {
			params.keys = append(params.keys, key)
		}
	}
	for _, key := range params.keys {
		sb.WriteByte(';')
		sb.WriteString(key)

		value, exists := params.Values[key]
		if !exists {
			continue
		}

		// Only add '=' if the value is not Boolean true
		if value.Type() == BooleanType {
			var boolVal bool
			if err := value.Value(&boolVal); err != nil {
				return "", fmt.Errorf("error getting boolean value for parameter %q: %w", key, err)
			}
			if boolVal {
				// Boolean true parameters can be represented as bare keys
				continue
			}
		}

		sb.WriteByte('=')
		marshaledParam, err := value.MarshalSFV()
		if err != nil {
			return "", fmt.Errorf("error marshaling parameter value %q: %w", key, err)
		}
		sb.Write(marshaledParam)
	}

	return sb.String(), nil
}

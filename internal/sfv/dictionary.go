package sfv

import "fmt"

type Dictionary struct {
	keys   []string
	values map[string]any
}

func NewDictionary() *Dictionary {
	return &Dictionary{
		keys:   make([]string, 0),
		values: make(map[string]any),
	}
}

func (d *Dictionary) Set(key string, value any) error {
	switch value.(type) {
	case *Item, *InnerList:
		// ok. no op
	default:
		return fmt.Errorf("value must be of type *Item or *InnerList, got %T", value)
	}

	if _, exists := d.values[key]; !exists {
		d.keys = append(d.keys, key)
	}
	d.values[key] = value
	return nil
}

func (d *Dictionary) Get(key string) (Value, bool) {
	value, exists := d.values[key]
	return value, exists
}

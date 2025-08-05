package sfv

type InnerList struct {
	values []Item
	params *Parameters
}

// Len returns the number of values in the inner list
func (il *InnerList) Len() int {
	if il == nil {
		return 0
	}
	return len(il.values)
}

// Get returns the value at the specified index
func (il *InnerList) Get(index int) (Item, bool) {
	if il == nil || index < 0 || index >= len(il.values) {
		return nil, false
	}
	return il.values[index], true
}

// Parameters returns the parameters associated with this InnerList
func (il *InnerList) Parameters() *Parameters {
	if il == nil {
		return nil
	}
	return il.params
}

type List struct {
	values []any
}

// Len returns the number of values in the list
func (l *List) Len() int {
	if l == nil {
		return 0
	}
	return len(l.values)
}

// Get returns the value at the specified index
func (l *List) Get(index int) (any, bool) {
	if l == nil || index < 0 || index >= len(l.values) {
		return nil, false
	}
	return l.values[index], true
}

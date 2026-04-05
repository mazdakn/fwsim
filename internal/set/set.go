package set

// SetType is a generic set data type.
type SetType[T comparable] struct {
	items map[T]struct{}
}

// New returns an empty SetType.
func New[T comparable]() *SetType[T] {
	return &SetType[T]{items: make(map[T]struct{})}
}

// Add inserts item into the set.
func (s *SetType[T]) Add(item T) {
	s.items[item] = struct{}{}
}

// Delete removes item from the set.
func (s *SetType[T]) Delete(item T) {
	delete(s.items, item)
}

// Exists reports whether item is present in the set.
func (s *SetType[T]) Exists(item T) bool {
	_, ok := s.items[item]
	return ok
}

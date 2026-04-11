package set

// Set is a generic set data type.
type Set[T comparable] struct {
	items map[T]struct{}
}

// New returns an empty Set.
func New[T comparable]() *Set[T] {
	return &Set[T]{items: make(map[T]struct{})}
}

// Add inserts item into the set.
func (s *Set[T]) Add(item T) {
	s.items[item] = struct{}{}
}

// Delete removes item from the set.
func (s *Set[T]) Delete(item T) {
	delete(s.items, item)
}

// Exists reports whether item is present in the set.
func (s *Set[T]) Exists(item T) bool {
	_, ok := s.items[item]
	return ok
}

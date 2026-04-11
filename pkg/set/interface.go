package set

type Set interface {
	Add(any) error
	Match(any) bool
}

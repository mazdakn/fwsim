package set

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestSetAdd(t *testing.T) {
	RegisterTestingT(t)

	s := New[string]()

	s.Add("foo")
	Expect(s.Exists("foo")).To(BeTrue())
	Expect(s.Exists("bar")).To(BeFalse())
}

func TestSetDelete(t *testing.T) {
	RegisterTestingT(t)

	s := New[int]()

	s.Add(1)
	s.Add(2)
	Expect(s.Exists(1)).To(BeTrue())

	s.Delete(1)
	Expect(s.Exists(1)).To(BeFalse())
	Expect(s.Exists(2)).To(BeTrue())
}

func TestSetExists(t *testing.T) {
	RegisterTestingT(t)

	s := New[string]()

	Expect(s.Exists("missing")).To(BeFalse())

	s.Add("present")
	Expect(s.Exists("present")).To(BeTrue())
	Expect(s.Exists("missing")).To(BeFalse())
}

func TestPortSetAdd(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()

	ps.Add(80)
	Expect(ps.Match(80)).To(BeTrue())
	Expect(ps.Match(443)).To(BeFalse())
}

func TestPortSetDelete(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()

	ps.Add(80)
	ps.Add(443)
	Expect(ps.Match(80)).To(BeTrue())

	ps.Delete(80)
	Expect(ps.Match(80)).To(BeFalse())
	Expect(ps.Match(443)).To(BeTrue())
}

func TestPortSetMatch(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()

	Expect(ps.Match(80)).To(BeFalse())

	ps.Add(80)
	Expect(ps.Match(80)).To(BeTrue())
	Expect(ps.Match(8080)).To(BeFalse())
}

func TestPortSetStringOnePort(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()
	ps.Add(80)
	Expect(ps.String()).To(Equal("80"))
}

func TestPortSetStringMultiplePorts(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()
	ps.Add(443)
	ps.Add(80)
	Expect(ps.String()).To(Equal("{80,443}"))
}

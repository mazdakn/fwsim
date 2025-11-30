package link

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestNew(t *testing.T) {
	RegisterTestingT(t)

	t.Run("creates new link", func(t *testing.T) {
		l := New()
		Expect(l).ToNot(BeNil())
		Expect(l.link).ToNot(BeNil())
	})

	t.Run("multiple links are independent", func(t *testing.T) {
		l1 := New()
		l2 := New()
		Expect(l1).ToNot(BeNil())
		Expect(l2).ToNot(BeNil())
		Expect(l1).ToNot(Equal(l2))
		Expect(l1.link).ToNot(Equal(l2.link))
	})
}

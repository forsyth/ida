package ida

import (
	"testing"
)

func all1(t *testing.T, what string, f func(a Field) bool) {
	for a := zero; a <= MaxVal; a++ {
		if !f(a) {
			t.Errorf("%s: %d: failed", what, a)
		}
	}
}

func all2(t *testing.T, what string, f func(a, b Field) bool) {
	for a := zero; a <= MaxVal; a++ {
		for b := MaxVal - 100; b <= MaxVal; b++ {
			if !f(a, b) {
				t.Errorf("%s: %d %d: failed", what, a, b)
			}
		}
	}
}

func all3(t *testing.T, what string, f func(a, b, c Field) bool) {
	for a := zero; a <= MaxVal; a++ {
		for b := MaxVal - 100; b <= MaxVal; b++ {
			for c := MaxVal - 100; c <= MaxVal; c++ {
				if !f(a, b, c) {
					t.Errorf("%s: %d %d %d:  failed", what, a, b, c)
				}
			}
		}
	}
}

func TestZp(t *testing.T) {
	t.Run("add", func(t *testing.T) {
		all2(t, "+ abelian", func(a, b Field) bool {
			return a.add(b) == b.add(a)
		})
		all3(t, "+ associative", func(a, b, c Field) bool {
			return a.add(b).add(c) == a.add(b.add(c))
		})
		all1(t, "+ identity", func(a Field) bool {
			return a.add(zero) == a && zero.add(a) == a
		})
		all1(t, "+ inverse", func(a Field) bool {
			return a.add((Prime-a)%Prime) == zero
		})
	})
	t.Run("mul", func(t *testing.T) {
		all2(t, "* abelian", func(a, b Field) bool {
			return a.mul(b) == b.mul(a)
		})
		all3(t, "* associative", func(a, b, c Field) bool {
			return a.mul(b).mul(c) == a.mul(b.mul(c))
		})
		all1(t, "* identity", func(a Field) bool {
			return a.mul(1) == Field(1).mul(a)
		})
		all1(t, "* inverse", func(a Field) bool {
			if a == 0 {
				return true
			}
			b := invtab[a]
			return a.mul(b) == 1 && b.mul(a) == 1
		})
		all3(t, "* distributes", func(a, b, c Field) bool {
			return a.mul(b.add(c)) == a.mul(b).add(a.mul(c))
		})
		if r := MaxVal.mul(MaxVal); r != 1 {
			t.Errorf("MaxVal*MaxVal: want 1; got %d", r)
		}
	})
}

//func BenchmarkTestZp(b *testing.B) {
//}

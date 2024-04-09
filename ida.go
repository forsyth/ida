// Package ida implements [Rabin]'s Information Dispersal Algorithm (IDA), an effective scheme
// for fault-tolerant storage and message routing.
// The algorithm breaks an array of bytes (for instance a file or a block of data) into n pieces,
// in such a way that the original data can be recovered using only m of them,
// where n and m are parameters.
//
// [Fragment] takes an array of data and m, the minimum number of pieces needed for reconstruction, and
// returns a [Frag] value representing one encoded fragment of the data.
// At least m calls must be made to [Fragment] to obtain enough such fragments to
// be able to rebuild the data; invariably more fragments are generated to provide
// the desired level of redundancy.
//
// [Reconstruct] takes an array frags of distinct fragments previously produced by repeated calls to
// [Fragment](data, m) and returns a tuple data, err.
// Provided at least m suitable fragments are found in frags, the data returned will be that
// originally provided to [Fragment]. If the parameters of the various fragments in frags
// disagree, or some other error occurs, data will be nil and err provides a diagnostic.
// [Reconstruct] assumes the fragments it receives are consistent:
// they represent the same encoding parameters, including the value of m.
// If it detects an inconsistency, it returns a diagnostic.
//
// [Consistent] checks the consistency of a set of fragments, and returns a new subset
// containing only those fragments the agree with the majority in frags on each parameter.
//
// [Rabin]: https://dl.acm.org/doi/10.1145/62044.62050
// M Rabin, “Efficient Dispersal of Information for Security,
// Load Balancing, and Fault Tolerance”, JACM 36(2), April 1989, pp. 335-348.
// The field Z(65537) used here is that suggested at the top of page 340.
package ida

import (
	"errors"
	"fmt"
)

var (
	ErrTooFewFragments      = errors.New("too few fragments")
	ErrInconsistentMatrix   = errors.New("inconsistent encoding matrix for reconstruction")
	ErrInconsistentFragment = errors.New("inconsistent fragment")
	ErrCorruptOutput        = errors.New("corrupt output: impossible value")
	ErrUnstableParameters   = errors.New("cannot find stable parameter values in this set")
	ErrNoConsistency        = errors.New("no consistent set found")
)

// Frag represents one fragment of a set of fragments that together redundantly represent the original data.
// The members are exported only to allow any available marshalling scheme to see them (gob, for instance).
// The value of all members must be stored and recovered for reconstruction.
type Frag struct {

	// Len is the length in bytes of the original data.
	Len int

	// M is the minimum pieces for reconstruction.
	M int

	// Encoding array row (of an MxM matrix) for this fragment, values in the interval [1, MaxVal]
	A []Field

	// Encoded data, length ceil(Len/2*M), values in the interval [0, MaxVal].
	Enc []int
}

// Fragment returns a Frag representing the encoded version of data, where
// at least m fragments are to be required to reconstruct the original data.
func Fragment(data []byte, m int) *Frag {
	nb := len(data)
	nw := (nb + 1) / 2
	a := randomVec(m)
	f := make([]int, (nw+m-1)/m)
	o := 0
	i := 0
	for _ = range f {
		c := zero
		for j := 0; j < m && i < nb; j++ {
			b := Field(data[i]) << 8
			i++
			if i < nb {
				b |= Field(data[i])
				i++
			}
			c = c.add(b.mul(a[j]))
		}
		f[o] = int(c)
		o++
	}
	return &Frag{Len: nb, M: m, A: a, Enc: f}
}

// Reconstruct returns the data encoded by the given consistent set of fragments.
// See [Consistent] for a function that can sort through an arbitrary set of fragments representing the same data
// and return a consistent set.
func Reconstruct(frags []*Frag) ([]byte, error) {
	if len(frags) < 1 || len(frags) < frags[0].M {
		return nil, ErrTooFewFragments
	}
	m := frags[0].M
	fraglen := len(frags[0].Enc)
	dlen := frags[0].Len

	a := NewMatrix(m)
	for j := range a {
		a[j] = frags[j].A
		if len(a[j]) != m {
			return nil, ErrInconsistentMatrix
		}
		if len(frags[j].Enc) != fraglen || frags[j].Len != dlen {
			return nil, ErrInconsistentFragment
		}
	}
	ainv, err := a.Invert()
	if err != nil {
		return nil, fmt.Errorf("invalid decoding matrix: %v", err)
	}
	out := make([]byte, fraglen*2*m)
	o := 0
	for k := range frags[0].Enc {
		for i := 0; i < m; i++ {
			row := ainv[i]
			b := zero
			for j := 0; j < m; j++ {
				b = b.add(Field(frags[j].Enc[k]).mul(row[j]))
			}
			if (b >> 16) != 0 {
				return nil, ErrCorruptOutput
			}
			out[o] = byte(b >> 8)
			o++
			if o < dlen {
				out[o] = byte(b)
				o++
			}
		}
	}
	if dlen < len(out) {
		out = out[0:dlen]
	}
	return out, nil
}

// val is one of the parameter values for a set of fragments.
// In the absence of error, a given parameter value should have the same value in all fragments,
// and there are typically only a handful of those, so slices are fine for linear search.
type val struct {
	v int // value
	n int // occurrence count
}

// addval adds v to list vals, either incrementing the count if it's already
// listed, or adding it to the list, returning the updated list.
func addval(vals []val, v int) []val {
	for l := range vals {
		if vals[l].v == v {
			vals[l].n++
			return vals
		}
	}
	return append(vals, val{v, 1})
}

// mostly returns the most popular value in list vals,
// returning a tuple (val, ok) where ok is true iff
// a value was found.
func mostly(vals []val) (int, bool) {
	v := val{0, -1}
	for _, lv := range vals {
		if lv.n > v.n {
			v = lv
		}
	}
	if v.n < 0 {
		return 0, false
	}
	return v.v, true
}

// Consistent returns a consistent set of Frags: all parameters agree with the majority,
// and obviously bad fragments have been discarded. If no such set can be found,
// Consistent returns an error.
func Consistent(frags []*Frag) ([]*Frag, error) {
	t := make([]*Frag, len(frags))
	copy(t[0:], frags)
	frags = t     // leave original untouched
	ds := []val{} // data size
	ms := []val{}
	fls := []val{}
	for _, f := range frags {
		if f != nil {
			ds = addval(ds, f.Len)
			ms = addval(ms, f.M)
			fls = addval(fls, len(f.Enc))
		}
	}
	dv, ok1 := mostly(ds)
	mv, ok2 := mostly(ms)
	flv, ok3 := mostly(fls)
	if !ok1 || !ok2 || !ok3 {
		return nil, ErrUnstableParameters
	}
	out := []*Frag{}
	for _, f := range frags {
		if f == nil || f.M != mv || f.M != len(f.A) || len(f.Enc) != flv || f.Len != dv || badfrag(f) { // inconsistent: drop it
			// inconsistent, drop it
			continue
		}
		out = append(out, f) // survivor to output list
	}
	if len(out) == 0 {
		return nil, ErrNoConsistency
	}
	return out, nil
}

// badfrag looks for implausible element values and returns true if it finds them.
func badfrag(f *Frag) bool {
	for _, v := range f.A {
		if v <= 0 || v >= Prime {
			return true
		}
	}
	for _, v := range f.Enc {
		if v < 0 || v >= Prime {
			return true
		}
	}
	return false
}

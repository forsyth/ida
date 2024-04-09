package ida

import (
	"errors"
	"fmt"
	"math/rand"
	"strings"
)

//go:generate go run ./cmd/mkidatab.go -prime 65537 -output zptab.go

// Field represents values of the finite field supporting IDA construction.
type Field uint32

// Matrix represents a matrix of values in Field.
type Matrix [][]Field

// Prime is the order of the field in this implementation.
// The order used here is that suggested at the top of page 340 in Rabin's published paper.
const Prime = 65537

// MaxVal is the largest value in the field.
const MaxVal Field = Prime - 1

// zero is the identity for addition.
const zero Field = 0

// operations in GF(Prime) (ie, mod Prime)

func (a Field) div(b Field) Field {
	return a.mul(Field(invtab[b]))
}

func (a Field) mul(b Field) Field {
	return Field((uint64(a) * uint64(b)) % Prime)
}

func (a Field) sub(b Field) Field {
	return ((a - b) + Prime) % Prime
}

func (a Field) add(b Field) Field {
	return (a + b) % Prime
}

// randomVec returns a slice of length m containing random Field values in the interval [1, MaxVal].
func randomVec(m int) []Field {
	a := make([]Field, m)
	for i := range a {
		a[i] = Field(rand.Intn(int(MaxVal))) + 1 // ensure no zero-value elements: 1..MaxVal
	}
	return a
}

var (
	ErrNonSquare = errors.New("decoding matrix must be square")
	ErrZeroPivot = errors.New("zero pivot value in decoding matrix")
)

// NewMatrix returns a new decoding matrix of rank m.
func NewMatrix(m int) Matrix {
	return make(Matrix, m)
}

// Invert inverts a matrix of Field values and returns that inverse, leaving the original matrix untouched.
// Rabin's paper gives a way of building an encoding matrix in Cauchy form that can then
// be inverted in O(m^2) operations, compared to O(m^3) for the following,
// but m is small enough it doesn't seem worth the added complication,
// and it's only done once per fragment set.
// Invert returns an error if there's a zero pivot value or non-square matrix.
func (a Matrix) Invert() (Matrix, error) {
	m := len(a) // it's square
	out := make(Matrix, m)
	// copy each row and add the adjacent identity matrix
	for r := 0; r < m; r++ {
		if len(a[r]) != m {
			return nil, ErrNonSquare
		}
		out[r] = make([]Field, m*2)
		copy(out[r], a[r])
		out[r][m+r] = 1 // identity matrix
	}
	for r := 0; r < m; r++ {
		x := out[r][r] // by construction, cannot be zero, unless later corrupted
		if x == 0 {
			return nil, ErrZeroPivot
		}
		for c := 0; c < 2*m; c++ {
			out[r][c] = out[r][c].div(x)
		}
		for r1 := 0; r1 < m; r1++ {
			if r1 != r {
				if out[r][r] == 0 {
					return nil, ErrZeroPivot
				}
				y := out[r1][r].div(out[r][r])
				for c := 0; c < 2*m; c++ {
					out[r1][c] = out[r1][c].sub(y.mul(out[r][c]))
				}
			}
		}
	}
	// remove the adjacent temporary matrix (now in front)
	for r := 0; r < m; r++ {
		out[r] = out[r][m:]
	}
	return out, nil
}

func (m Matrix) String() string {
	var sb strings.Builder
	for i := range m {
		for j := range m[i] {
			if j != 0 {
				sb.WriteByte(' ')
			}
			sb.WriteString(fmt.Sprint(m[i][j]))
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

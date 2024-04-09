package ida

// Copyright © 2024 charles.forsyth@gmail.com

import (
	"fmt"
	"math/rand"
	"os"
	"testing"
)

const debug = true
const nowrite = true
const onlyenc = false

func TestIDA(t *testing.T) {
	f, err := os.Open("ida_test.go")
	if err != nil {
		t.Fatal("cannot open ida_test.go")
	}
	defer f.Close()
	buf := make([]byte, 1024)
	for {
		n, _ := f.Read(buf)
		if n == 0 {
			if debug {
				fmt.Fprintf(os.Stderr, "EOF\n")
			}
			break
		}
		frags := make([]*Frag, 14)
		for x := 0; x < len(frags); x++ {
			f := Fragment(buf[0:n], 7)
			frags[x] = f
			if debug {
				fmt.Fprintf(os.Stderr, "frag[%d] %#v\n", x, f)
			}
		}
		if onlyenc {
			continue
		}
		if true {
			// shuffle
			for i := 0; i < len(frags); i++ {
				r := rand.Intn(len(frags))
				if r != i {
					t := frags[i]
					frags[i] = frags[r]
					frags[r] = t
				}
			}
		}
		//  recover
		zot, err := Reconstruct(frags)
		if err != nil {
			t.Errorf("reconstruction failed: %v", err)
			continue
		}
		if len(zot) != n {
			t.Errorf("bad length: want %d got %d", n, len(zot))
			continue
		}
		if debug {
			for i := range zot {
				fmt.Fprintf(os.Stderr, " %.2x", zot[i])
			}
			fmt.Fprintf(os.Stderr, "\n")
			fmt.Fprintf(os.Stderr, "%q\n", string(zot))
		} else if !nowrite {
			os.Stdout.Write(zot)
		}
	}
}

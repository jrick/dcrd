// Copyright (c) 2023 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"strings"
)

// MixVec is a N-element vector of Msize []byte messages.
type MixVec struct {
	N     uint32
	Msize uint32
	Data  []byte
}

// NewMixVec returns a zero vector for holding n messages of msize length.
func NewMixVec(n, msize uint32) *MixVec {
	return &MixVec{
		N:     n,
		Msize: msize,
		Data:  make([]byte, n*msize),
	}
}

func (v *MixVec) String() string {
	m := func(i int) []byte {
		off := uint32(i) * v.Msize
		return v.Data[off : off+v.Msize]
	}

	b := new(strings.Builder)
	b.Grow(2 + int(v.N*(2*v.Msize+1)))
	b.WriteString("[")
	for i := 0; uint32(i) < v.N; i++ {
		if i != 0 {
			b.WriteString(" ")
		}
		fmt.Fprintf(b, "%x", m(i))
	}
	b.WriteString("]")
	return b.String()
}

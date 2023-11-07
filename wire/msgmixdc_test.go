// Copyright (c) 2023 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/chaincfg/chainhash"
)

func TestMixDCWire(t *testing.T) {
	pver := MixVersion

	repeat := func(b byte, count int) []byte {
		s := make([]byte, count)
		for i := range s {
			s[i] = b
		}
		return s
	}

	// Create a fictitious message with easily-distinguishable fields.

	var sig [64]byte
	copy(sig[:], repeat(0x80, 64))

	var id [33]byte
	copy(id[:], repeat(0x81, 33))

	var sid [32]byte
	copy(sid[:], repeat(0x82, 32))

	const expiry = int64(0x0383838383838383)
	const run = uint32(0x84848484)

	mcount := 4
	var kpcount uint32 = 4
	dcnet := make([]MixVec, mcount)
	// will add 4x4 field numbers of incrementing repeating byte values to
	// dcnet, ranging from 0x85 through 0x94
	b := byte(0x85)
	for i := 0; i < mcount; i++ {
		dcnet[i].N = kpcount
		dcnet[i].Msize = 32
		for j := 0; j < int(kpcount); j++ {
			dcnet[i].Data = append(dcnet[i].Data, repeat(b, 32)...)
			b++
		}
	}

	seenSRs := make([]chainhash.Hash, 4)
	for b := byte(0x95); b < 0x99; b++ {
		copy(seenSRs[b-0x95][:], repeat(b, 32))
	}

	dc := NewMsgMixDC(id, sid, expiry, run, dcnet, seenSRs)
	dc.Signature = sig

	buf := new(bytes.Buffer)
	err := dc.BtcEncode(buf, pver)
	if err != nil {
		t.Fatal(err)
	}

	decodedDC := new(MsgMixDC)
	err = decodedDC.BtcDecode(bytes.NewReader(buf.Bytes()), pver)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(dc, decodedDC) {
		t.Errorf("BtcDecode got: %s want: %s",
			spew.Sdump(decodedDC), spew.Sdump(dc))
	} else {
		t.Logf("bytes: %x", buf.Bytes())
		t.Logf("spew: %s", spew.Sdump(decodedDC))
	}
}

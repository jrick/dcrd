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

func TestMixSRWire(t *testing.T) {
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
	kpcount := 4
	dcmix := make([][][]byte, mcount)
	// will add 4x4 field numbers of incrementing repeating byte values to
	// dcmix, ranging from 0x85 through 0x94
	b := byte(0x85)
	for i := 0; i < mcount; i++ {
		dcmix[i] = make([][]byte, kpcount)
		for j := 0; j < kpcount; j++ {
			dcmix[i][j] = repeat(b, 32)
			b++
		}
	}

	seenCTs := make([]chainhash.Hash, 4)
	for b := byte(0x95); b < 0x99; b++ {
		copy(seenCTs[b-0x95][:], repeat(b, 32))
	}

	sr := NewMsgMixSR(id, sid, expiry, run, dcmix, seenCTs)
	sr.Signature = sig

	buf := new(bytes.Buffer)
	err := sr.BtcEncode(buf, pver)
	if err != nil {
		t.Fatal(err)
	}

	decodedSR := new(MsgMixSR)
	err = decodedSR.BtcDecode(bytes.NewReader(buf.Bytes()), pver)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(sr, decodedSR) {
		t.Errorf("BtcDecode got: %s want: %s",
			spew.Sdump(decodedSR), spew.Sdump(sr))
	} else {
		t.Logf("bytes: %x", buf.Bytes())
		t.Logf("spew: %s", spew.Sdump(decodedSR))
	}
}

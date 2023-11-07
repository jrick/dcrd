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

func TestMixCTWire(t *testing.T) {
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

	cts := make([][1047]byte, 4)
	for b := byte(0x85); b < 0x89; b++ {
		copy(cts[b-0x85][:], repeat(b, 1047))
	}

	seenKEs := make([]chainhash.Hash, 4)
	for b := byte(0x89); b < 0x8D; b++ {
		copy(seenKEs[b-0x89][:], repeat(b, 32))
	}

	ct := NewMsgMixCT(id, sid, expiry, run, cts, seenKEs)
	ct.Signature = sig

	buf := new(bytes.Buffer)
	err := ct.BtcEncode(buf, pver)
	if err != nil {
		t.Fatal(err)
	}

	decodedCT := new(MsgMixCT)
	err = decodedCT.BtcDecode(bytes.NewReader(buf.Bytes()), pver)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(ct, decodedCT) {
		t.Errorf("BtcDecode got: %s want: %s",
			spew.Sdump(decodedCT), spew.Sdump(ct))
	} else {
		t.Logf("bytes: %x", buf.Bytes())
		t.Logf("spew: %s", spew.Sdump(decodedCT))
	}
}

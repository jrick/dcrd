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

func TestMixKEWire(t *testing.T) {
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

	var ecdh [33]byte
	copy(ecdh[:], repeat(0x85, 33))

	var pqpk [1218]byte
	copy(pqpk[:], repeat(0x86, 1218))

	var commitment [32]byte
	copy(commitment[:], repeat(0x87, 32))

	seenPRs := make([]chainhash.Hash, 4)
	for b := byte(0x88); b < 0x8C; b++ {
		copy(seenPRs[b-0x88][:], repeat(b, 32))
	}

	ke := NewMsgMixKE(id, sid, expiry, run, ecdh, pqpk, commitment, seenPRs)
	ke.Signature = sig

	buf := new(bytes.Buffer)
	err := ke.BtcEncode(buf, pver)
	if err != nil {
		t.Fatal(err)
	}

	decodedKE := new(MsgMixKE)
	err = decodedKE.BtcDecode(bytes.NewReader(buf.Bytes()), pver)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(ke, decodedKE) {
		t.Errorf("BtcDecode got: %s want: %s",
			spew.Sdump(decodedKE), spew.Sdump(ke))
	} else {
		t.Logf("bytes: %x", buf.Bytes())
		t.Logf("spew: %s", spew.Sdump(decodedKE))
	}
}

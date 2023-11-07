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

func TestMixPRWire(t *testing.T) {
	pver := MixVersion

	repeat := func(b byte, count int) []byte {
		s := make([]byte, count)
		for i := range s {
			s[i] = b
		}
		return s
	}
	rhash := func(b byte) chainhash.Hash {
		var h chainhash.Hash
		for i := range h {
			h[i] = b
		}
		return h
	}

	// Create a fictitious message with easily-distinguishable fields.

	var sig [64]byte
	copy(sig[:], repeat(0x80, 64))

	var id [33]byte
	copy(id[:], repeat(0x81, 33))

	const expiry = int64(0x0282828282828282)
	const mixAmount = int64(0x0383838383838383)
	const sc = "P2PKH-secp256k1-v0"
	const txVersion = uint16(0x8484)
	const lockTime = uint32(0x85858585)
	const messageCount = uint32(0x86868686)
	const inputValue = int64(0x0787878787878787)

	utxos := []MixPRUTXO{
		{
			OutPoint: OutPoint{
				Hash:  rhash(0x88),
				Index: 0x89898989,
				Tree:  0x0A,
			},
			Script:    []byte{},
			PubKey:    repeat(0x8B, 33),
			Signature: repeat(0x8C, 64),
		},
		{
			OutPoint: OutPoint{
				Hash:  rhash(0x8D),
				Index: 0x8E8E8E8E,
				Tree:  0x0F,
			},
			Script:    repeat(0x90, 25),
			PubKey:    repeat(0x91, 33),
			Signature: repeat(0x92, 64),
		},
	}

	const changeValue = int64(0x1393939393939393)
	pkScript := repeat(0x94, 25)
	change := NewTxOut(changeValue, pkScript)

	pr, err := NewMsgMixPR(id, expiry, mixAmount, sc, txVersion, lockTime,
		messageCount, inputValue, utxos, change)
	if err != nil {
		t.Fatal(err)
	}
	pr.Signature = sig

	buf := new(bytes.Buffer)
	err = pr.BtcEncode(buf, pver)
	if err != nil {
		t.Fatal(err)
	}

	decodedPR := new(MsgMixPR)
	err = decodedPR.BtcDecode(bytes.NewReader(buf.Bytes()), pver)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(pr, decodedPR) {
		t.Errorf("BtcDecode got: %s want: %s",
			spew.Sdump(decodedPR), spew.Sdump(pr))
	} else {
		t.Logf("bytes: %x", buf.Bytes())
		t.Logf("spew: %s", spew.Sdump(decodedPR))
	}
}

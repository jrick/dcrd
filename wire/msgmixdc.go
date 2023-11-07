// Copyright (c) 2023 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"

	"github.com/decred/dcrd/chaincfg/chainhash"
)

// MsgMixDC is the DC-net broadcast.  It implements the Message interface.
type MsgMixDC struct {
	Signature [64]byte
	Identity  [33]byte
	SessionID [32]byte
	Expiry    int64
	Run       uint32
	DCNet     []MixVec
	SeenSRs   []chainhash.Hash
}

// BtcDecode decodes r using the Decred protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgMixDC) BtcDecode(r io.Reader, pver uint32) error {
	const op = "MsgMixDC.BtcDecode"
	if pver < MixVersion {
		msg := fmt.Sprintf("%s message invalid for protocol version %d",
			msg.Command(), pver)
		return messageError(op, ErrMsgInvalidForPVer, msg)
	}

	err := readElements(r, &msg.Signature, &msg.Identity, &msg.SessionID,
		&msg.Expiry, &msg.Run)
	if err != nil {
		return err
	}

	mcount, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	if mcount > MaxMixMcount {
		msg := fmt.Sprintf("too many total mixed messages [%v]", mcount)
		return messageError(op, ErrInvalidMsg, msg)
	}

	dcnet := make([]MixVec, mcount)
	for i := range dcnet {
		err := readMixVec(op, r, pver, &dcnet[i])
		if err != nil {
			return err
		}
	}
	msg.DCNet = dcnet

	count, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	if count > MaxPrevMixMsgs {
		msg := fmt.Sprintf("too many previous referenced messages [%v]", count)
		return messageError(op, ErrTooManyPrevMixMsgs, msg)
	}

	seen := make([]chainhash.Hash, count)
	for i := range seen {
		err := readElement(r, &seen[i])
		if err != nil {
			return err
		}
	}
	msg.SeenSRs = seen

	return nil
}

// BtcEncode encodes the receiver to w using the Decred protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgMixDC) BtcEncode(w io.Writer, pver uint32) error {
	const op = "MsgMixDC.BtcEncode"
	if pver < MixVersion {
		msg := fmt.Sprintf("%s message invalid for protocol version %d",
			msg.Command(), pver)
		return messageError(op, ErrMsgInvalidForPVer, msg)
	}

	err := writeElement(w, &msg.Signature)
	if err != nil {
		return err
	}

	err = msg.writeMessageNoSignature(op, w, pver)
	if err != nil {
		return err
	}

	return nil
}

// writeMessageNoSignature serializes all elements of the message except for
// the signature.  This allows code reuse between message serialization, and
// signing and verifying these message contents.
func (msg *MsgMixDC) writeMessageNoSignature(op string, w io.Writer, pver uint32) error {
	err := writeElements(w, &msg.Identity, &msg.SessionID, msg.Expiry,
		msg.Run)
	if err != nil {
		return err
	}

	mcount := len(msg.DCNet)
	if mcount == 0 {
		msg := fmt.Sprintf("too few mixed messages [%v]", mcount)
		return messageError(op, ErrInvalidMsg, msg)
	}
	if mcount > MaxMixMcount {
		msg := fmt.Sprintf("too many total mixed messages [%v]", mcount)
		return messageError(op, ErrInvalidMsg, msg)
	}
	err = WriteVarInt(w, pver, uint64(mcount))
	if err != nil {
		return err
	}

	for i := range msg.DCNet {
		err := writeMixVec(w, pver, &msg.DCNet[i])
		if err != nil {
			return err
		}
	}

	count := len(msg.SeenSRs)
	if count > MaxPrevMixMsgs {
		msg := fmt.Sprintf("too many previous referenced messages [%v]", count)
		return messageError(op, ErrTooManyPrevMixMsgs, msg)
	}

	err = WriteVarInt(w, pver, uint64(count))
	if err != nil {
		return err
	}
	for i := range msg.SeenSRs {
		err = writeElement(w, &msg.SeenSRs[i])
		if err != nil {
			return err
		}
	}

	return nil
}

func writeMixVec(w io.Writer, pver uint32, vec *MixVec) error {
	err := WriteVarInt(w, pver, uint64(vec.N))
	if err != nil {
		return err
	}
	err = WriteVarInt(w, pver, uint64(vec.Msize))
	if err != nil {
		return err
	}
	err = WriteVarBytes(w, pver, vec.Data)
	if err != nil {
		return err
	}

	return nil
}

func readMixVec(op string, r io.Reader, pver uint32, vec *MixVec) error {
	n, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	if n > MaxMixKPCount {
		msg := "too many mixing peers"
		return messageError(op, ErrInvalidMsg, msg)
	}
	msize, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	if msize > 32 {
		msg := "mixed message length exceeds max"
		return messageError(op, ErrInvalidMsg, msg)
	}
	data, err := ReadVarBytes(r, pver, MaxMixKPCount*32, "Data")
	if err != nil {
		return err
	}
	if int(n*msize) != len(data) {
		msg := "vec dimensions do not match data length"
		return messageError(op, ErrInvalidMsg, msg)
	}

	vec.N = uint32(n)
	vec.Msize = uint32(msize)
	vec.Data = data

	return nil
}

// WriteSigned writes a tag identifying the message data, followed by all
// message fields excluding the signature.  This is the data committed to when
// the message is signed.
func (msg *MsgMixDC) WriteSigned(w io.Writer) error {
	const op = "MsgMixDC.WriteSigned"

	err := WriteVarString(w, MixVersion, CmdMixDC+"-sig")
	if err != nil {
		return err
	}

	err = msg.writeMessageNoSignature(op, w, MixVersion)
	if err != nil {
		return err
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgMixDC) Command() string {
	return CmdMixDC
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgMixDC) MaxPayloadLength(pver uint32) uint32 {
	return 16800915
}

// Hash returns the hash of the serialized message.
func (msg *MsgMixDC) Hash() chainhash.Hash {
	return mustHash(msg, MixVersion)
}

// GetIdentity returns the message sender's public key identity.
func (msg *MsgMixDC) GetIdentity() []byte {
	return msg.Identity[:]
}

// GetSignature returns the message signature.
func (msg *MsgMixDC) GetSignature() []byte {
	return msg.Signature[:]
}

// Expires returns the block height at which the message expires.
func (msg *MsgMixDC) Expires() int64 {
	return msg.Expiry
}

// PrevMsgs returns the previous SR messages seen by the peer.
func (msg *MsgMixDC) PrevMsgs() []chainhash.Hash {
	return msg.SeenSRs
}

// Sid returns the session ID.
func (msg *MsgMixDC) Sid() []byte {
	return msg.SessionID[:]
}

// GetRun returns the run number.
func (msg *MsgMixDC) GetRun() uint32 {
	return msg.Run
}

// NewMsgMixDC returns a new mixsr message that conforms to the Message
// interface using the passed parameters and defaults for the remaining fields.
func NewMsgMixDC(identity [33]byte, sid [32]byte, expiry int64, run uint32,
	dcnet []MixVec, seenSRs []chainhash.Hash) *MsgMixDC {

	return &MsgMixDC{
		Identity:  identity,
		SessionID: sid,
		Expiry:    expiry,
		Run:       run,
		DCNet:     dcnet,
		SeenSRs:   seenSRs,
	}
}

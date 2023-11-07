// Copyright (c) 2023 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"

	"github.com/decred/dcrd/chaincfg/chainhash"
)

const (
	// MaxMixMcount is the maximum number of mixed messages that are allowed
	// in a single mix.  This restricts the total allowed size of the slot
	// reservation and XOR DC-net matrices.
	MaxMixMcount = 1024 // XXX: PNOOMA

	// MaxMixKPCount is the maximum number of peers allowed together in a
	// single mix.  This restricts the total size of the slot reservation
	// and XOR DC-net matrices.
	MaxMixKPCount = 512 // XXX: PNOOMA

	// MaxMixFieldValLen is the maximum number of bytes allowed to represent
	// a value in the slot reservation mix bounded by the field prime.
	MaxMixFieldValLen = 32
)

// MsgMixSR is the slot reservation broadcast.  It implements the Message
// interface.
type MsgMixSR struct {
	Signature [64]byte
	Identity  [33]byte
	SessionID [32]byte
	Expiry    int64
	Run       uint32
	DCMix     [][][]byte // mcount-by-peers matrix of field numbers
	SeenCTs   []chainhash.Hash
}

// BtcDecode decodes r using the Decred protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgMixSR) BtcDecode(r io.Reader, pver uint32) error {
	const op = "MsgMixSR.BtcDecode"
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

	// Read the DCMix
	mcount, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	kpcount, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	if mcount == 0 {
		msg := fmt.Sprintf("too few mixed messages [%v]", mcount)
		return messageError(op, ErrInvalidMsg, msg)
	}
	if mcount > MaxMixMcount {
		msg := fmt.Sprintf("too many total mixed messages [%v]", mcount)
		return messageError(op, ErrInvalidMsg, msg)
	}
	if mcount == 0 {
		msg := fmt.Sprintf("too few mixing peers [%v]", kpcount)
		return messageError(op, ErrInvalidMsg, msg)
	}
	if kpcount > MaxMixKPCount {
		msg := fmt.Sprintf("too many mixing peers [%v]", kpcount)
		return messageError(op, ErrInvalidMsg, msg)
	}
	dcmix := make([][][]byte, mcount)
	for i := range dcmix {
		dcmix[i] = make([][]byte, kpcount)
		for j := range dcmix[i] {
			v, err := ReadVarBytes(r, pver, MaxMixFieldValLen, "fieldval")
			if err != nil {
				return err
			}
			dcmix[i][j] = v
		}
	}
	msg.DCMix = dcmix

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
	msg.SeenCTs = seen

	return nil
}

// BtcEncode encodes the receiver to w using the Decred protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgMixSR) BtcEncode(w io.Writer, pver uint32) error {
	const op = "MsgMixSR.BtcEncode"
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
func (msg *MsgMixSR) writeMessageNoSignature(op string, w io.Writer, pver uint32) error {
	err := writeElements(w, &msg.Identity, &msg.SessionID, msg.Expiry,
		msg.Run)
	if err != nil {
		return err
	}

	// Write the DCMix
	mcount := len(msg.DCMix)
	if mcount == 0 {
		msg := fmt.Sprintf("too few mixed messages [%v]", mcount)
		return messageError(op, ErrInvalidMsg, msg)
	}
	if mcount > MaxMixMcount {
		msg := fmt.Sprintf("too many total mixed messages [%v]", mcount)
		return messageError(op, ErrInvalidMsg, msg)
	}
	kpcount := len(msg.DCMix[0])
	if kpcount == 0 {
		msg := fmt.Sprintf("too few mixing peers [%v]", kpcount)
		return messageError(op, ErrInvalidMsg, msg)
	}
	if kpcount > MaxMixKPCount {
		msg := fmt.Sprintf("too many mixing peers [%v]", kpcount)
		return messageError(op, ErrInvalidMsg, msg)
	}
	err = WriteVarInt(w, pver, uint64(mcount))
	if err != nil {
		return err
	}
	err = WriteVarInt(w, pver, uint64(kpcount))
	if err != nil {
		return err
	}
	for i := range msg.DCMix {
		if len(msg.DCMix[i]) != kpcount {
			msg := "invalid matrix dimensions"
			return messageError(op, ErrInvalidMsg, msg)
		}
		for j := range msg.DCMix[i] {
			v := msg.DCMix[i][j]
			if len(v) > MaxMixFieldValLen {
				msg := "value exceeds bytes necessary to represent number in field"
				return messageError(op, ErrInvalidMsg, msg)
			}
			err := WriteVarBytes(w, pver, v)
			if err != nil {
				return err
			}
		}
	}

	count := len(msg.SeenCTs)
	if count > MaxPrevMixMsgs {
		msg := fmt.Sprintf("too many previous referenced messages [%v]", count)
		return messageError(op, ErrTooManyPrevMixMsgs, msg)
	}

	err = WriteVarInt(w, pver, uint64(count))
	if err != nil {
		return err
	}
	for i := range msg.SeenCTs {
		err = writeElement(w, &msg.SeenCTs[i])
		if err != nil {
			return err
		}
	}

	return nil
}

// WriteSigned writes a tag identifying the message data, followed by all
// message fields excluding the signature.  This is the data committed to when
// the message is signed.
func (msg *MsgMixSR) WriteSigned(w io.Writer) error {
	const op = "MsgMixSR.WriteSigned"

	err := WriteVarString(w, MixVersion, CmdMixSR+"-sig")
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
func (msg *MsgMixSR) Command() string {
	return CmdMixSR
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgMixSR) MaxPayloadLength(pver uint32) uint32 {
	return 17318038
}

// Hash returns the hash of the serialized message.
func (msg *MsgMixSR) Hash() chainhash.Hash {
	return mustHash(msg, MixVersion)
}

// GetIdentity returns the message sender's public key identity.
func (msg *MsgMixSR) GetIdentity() []byte {
	return msg.Identity[:]
}

// GetSignature returns the message signature.
func (msg *MsgMixSR) GetSignature() []byte {
	return msg.Signature[:]
}

// Expires returns the block height at which the message expires.
func (msg *MsgMixSR) Expires() int64 {
	return msg.Expiry
}

// PrevMsgs returns the previous CT messages seen by the peer.
func (msg *MsgMixSR) PrevMsgs() []chainhash.Hash {
	return msg.SeenCTs
}

// Sid returns the session ID.
func (msg *MsgMixSR) Sid() []byte {
	return msg.SessionID[:]
}

// GetRun returns the run number.
func (msg *MsgMixSR) GetRun() uint32 {
	return msg.Run
}

// NewMsgMixSR returns a new mixsr message that conforms to the Message
// interface using the passed parameters and defaults for the remaining fields.
func NewMsgMixSR(identity [33]byte, sid [32]byte, expires int64, run uint32,
	dcmix [][][]byte, seenCTs []chainhash.Hash) *MsgMixSR {

	return &MsgMixSR{
		Identity:  identity,
		SessionID: sid,
		Expiry:    expires,
		Run:       run,
		DCMix:     dcmix,
		SeenCTs:   seenCTs,
	}
}

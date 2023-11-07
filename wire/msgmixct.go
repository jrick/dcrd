// Copyright (c) 2023 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"

	"github.com/decred/dcrd/chaincfg/chainhash"
)

// MsgMixCT is used by mixing peers to share SNTRUP4591761 ciphertexts with
// other peers who have published their public keys.  It implements the Message
// interface.
type MsgMixCT struct {
	Signature   [64]byte
	Identity    [33]byte
	SessionID   [32]byte
	Expiry      int64
	Run         uint32
	Ciphertexts [][1047]byte
	SeenKEs     []chainhash.Hash
}

// BtcDecode decodes r using the Decred protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgMixCT) BtcDecode(r io.Reader, pver uint32) error {
	const op = "MsgMixCT.BtcDecode"
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

	// Count is of both Ciphertexts and SeenKEs.
	count, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	if count > MaxPrevMixMsgs {
		msg := fmt.Sprintf("too many previous referenced messages [%v]", count)
		return messageError(op, ErrTooManyPrevMixMsgs, msg)
	}

	ciphertexts := make([][1047]byte, count)
	for i := range ciphertexts {
		err := readElement(r, &ciphertexts[i])
		if err != nil {
			return err
		}
	}
	msg.Ciphertexts = ciphertexts

	seen := make([]chainhash.Hash, count)
	for i := range seen {
		err := readElement(r, &seen[i])
		if err != nil {
			return err
		}
	}
	msg.SeenKEs = seen

	return nil
}

// BtcEncode encodes the receiver to w using the Decred protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgMixCT) BtcEncode(w io.Writer, pver uint32) error {
	const op = "MsgMixCT.BtcEncode"
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
func (msg *MsgMixCT) writeMessageNoSignature(op string, w io.Writer, pver uint32) error {
	err := writeElements(w, &msg.Identity, &msg.SessionID, msg.Expiry,
		msg.Run)
	if err != nil {
		return err
	}

	count := len(msg.Ciphertexts)
	if count != len(msg.SeenKEs) {
		msg := "differing counts of ciphertexts and seen KE messages"
		return messageError(op, ErrInvalidMsg, msg)
	}
	if count > MaxPrevMixMsgs {
		msg := fmt.Sprintf("too many previous referenced messages [%v]", count)
		return messageError(op, ErrTooManyPrevMixMsgs, msg)
	}

	err = WriteVarInt(w, pver, uint64(count))
	if err != nil {
		return err
	}
	for i := range msg.Ciphertexts {
		err = writeElement(w, &msg.Ciphertexts[i])
		if err != nil {
			return err
		}
	}
	for i := range msg.SeenKEs {
		err = writeElement(w, &msg.SeenKEs[i])
		if err != nil {
			return err
		}
	}

	return nil
}

// WriteSigned writes a tag identifying the message data, followed by all
// message fields excluding the signature.  This is the data committed to when
// the message is signed.
func (msg *MsgMixCT) WriteSigned(w io.Writer) error {
	const op = "MsgMixCT.WriteSigned"

	err := WriteVarString(w, MixVersion, CmdMixCT+"-sig")
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
func (msg *MsgMixCT) Command() string {
	return CmdMixCT
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgMixCT) MaxPayloadLength(pver uint32) uint32 {
	return 552592
}

// Hash returns the hash of the serialized message.
func (msg *MsgMixCT) Hash() chainhash.Hash {
	return mustHash(msg, MixVersion)
}

// GetIdentity returns the message sender's public key identity.
func (msg *MsgMixCT) GetIdentity() []byte {
	return msg.Identity[:]
}

// GetSignature returns the message signature.
func (msg *MsgMixCT) GetSignature() []byte {
	return msg.Signature[:]
}

// Expires returns the block height at which the message expires.
func (msg *MsgMixCT) Expires() int64 {
	return msg.Expiry
}

// PrevMsgs returns the previous KE messages seen by the peer.
func (msg *MsgMixCT) PrevMsgs() []chainhash.Hash {
	return msg.SeenKEs
}

// Sid returns the session ID.
func (msg *MsgMixCT) Sid() []byte {
	return msg.SessionID[:]
}

// GetRun returns the run number.
func (msg *MsgMixCT) GetRun() uint32 {
	return msg.Run
}

// NewMsgMixCT returns a new mixct message that conforms to the Message
// interface using the passed parameters and defaults for the remaining fields.
func NewMsgMixCT(identity [33]byte, sid [32]byte, expires int64, run uint32,
	ciphertexts [][1047]byte, seenKEs []chainhash.Hash) *MsgMixCT {

	return &MsgMixCT{
		Identity:    identity,
		SessionID:   sid,
		Expiry:      expires,
		Run:         run,
		Ciphertexts: ciphertexts,
		SeenKEs:     seenKEs,
	}
}

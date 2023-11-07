// Copyright (c) 2023 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"

	"github.com/decred/dcrd/chaincfg/chainhash"
)

// MsgMixRS reveals secrets of a failed mix run.  After secrets are exposed,
// peers can determine which peers (if any) misbehaved and remove them from the
// next run in the session.
//
// It implements the Message interface.
type MsgMixRS struct {
	Signature [64]byte
	Identity  [33]byte
	SessionID [32]byte
	Expiry    int64
	Run       uint32
	Seed      [32]byte
	SR        [][]byte
	M         [][]byte
}

// BtcDecode decodes r using the Decred protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgMixRS) BtcDecode(r io.Reader, pver uint32) error {
	const op = "MsgMixRS.BtcDecode"
	if pver < MixVersion {
		msg := fmt.Sprintf("%s message invalid for protocol version %d",
			msg.Command(), pver)
		return messageError(op, ErrMsgInvalidForPVer, msg)
	}

	err := readElements(r, &msg.Signature, &msg.Identity, &msg.SessionID,
		&msg.Expiry, &msg.Run, &msg.Seed)
	if err != nil {
		return err
	}

	var numSRs uint64
	err = readElement(r, &numSRs)
	if err != nil {
		return err
	}
	if numSRs > MaxMixMcount {
		msg := fmt.Sprintf("too many total mixed messages [%v]", numSRs)
		return messageError(op, ErrInvalidMsg, msg)
	}
	msg.SR = make([][]byte, numSRs)
	for i := uint64(0); i < numSRs; i++ {
		sr, err := ReadVarBytes(r, pver, MaxMixFieldValLen, "SR")
		if err != nil {
			return err
		}
		msg.SR[i] = sr
	}

	var numMs uint64
	err = readElement(r, &numMs)
	if err != nil {
		return err
	}
	if numMs > MaxMixMcount {
		msg := fmt.Sprintf("too many total mixed messages [%v]", numMs)
		return messageError(op, ErrInvalidMsg, msg)
	}
	msg.M = make([][]byte, numMs)
	for i := uint64(0); i < numMs; i++ {
		m, err := ReadVarBytes(r, pver, MaxMixFieldValLen, "M")
		if err != nil {
			return err
		}
		msg.M[i] = m
	}

	return nil
}

// BtcEncode encodes the receiver to w using the Decred protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgMixRS) BtcEncode(w io.Writer, pver uint32) error {
	const op = "MsgMixRS.BtcEncode"
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
func (msg *MsgMixRS) writeMessageNoSignature(op string, w io.Writer, pver uint32) error {
	err := writeElements(w, &msg.Identity, &msg.SessionID, msg.Expiry,
		msg.Run, &msg.Seed)
	if err != nil {
		return err
	}

	err = writeElement(w, uint64(len(msg.SR)))
	if err != nil {
		return err
	}
	for _, sr := range msg.SR {
		err := WriteVarBytes(w, pver, sr)
		if err != nil {
			return err
		}
	}

	err = writeElement(w, uint64(len(msg.M)))
	if err != nil {
		return err
	}
	for _, m := range msg.M {
		err := WriteVarBytes(w, pver, m)
		if err != nil {
			return err
		}
	}

	return nil
}

// WriteSigned writes a tag identifying the message data, followed by all
// message fields excluding the signature.  This is the data committed to when
// the message is signed.
func (msg *MsgMixRS) WriteSigned(w io.Writer) error {
	const op = "MsgMixRS.WriteSigned"

	err := WriteVarString(w, MixVersion, CmdMixRS+"-sig")
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
func (msg *MsgMixRS) Command() string {
	return CmdMixRS
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgMixRS) MaxPayloadLength(pver uint32) uint32 {
	return 67773
}

// Hash returns the hash of the serialized message.
func (msg *MsgMixRS) Hash() chainhash.Hash {
	return mustHash(msg, MixVersion)
}

// GetIdentity returns the message sender's public key identity.
func (msg *MsgMixRS) GetIdentity() []byte {
	return msg.Identity[:]
}

// GetSignature returns the message signature.
func (msg *MsgMixRS) GetSignature() []byte {
	return msg.Signature[:]
}

// Expires returns the block height at which the message expires.
func (msg *MsgMixRS) Expires() int64 {
	return msg.Expiry
}

// PrevMsgs returns the previous DC messages seen by the peer.
func (msg *MsgMixRS) PrevMsgs() []chainhash.Hash {
	return nil // XXX
}

// Sid returns the session ID.
func (msg *MsgMixRS) Sid() []byte {
	return msg.SessionID[:]
}

// GetRun returns the run number.
func (msg *MsgMixRS) GetRun() uint32 {
	return msg.Run
}

// NewMsgMixRS returns a new mixke message that conforms to the Message
// interface using the passed parameters and defaults for the remaining fields.
func NewMsgMixRS(identity [33]byte, sid [32]byte, expiry int64, run uint32,
	seed [32]byte, srMsgs [][]byte, dcMsgs [][]byte) *MsgMixRS {

	return &MsgMixRS{
		Identity:  identity,
		SessionID: sid,
		Expiry:    expiry,
		Run:       run,
		Seed:      seed,
		SR:        srMsgs,
		M:         dcMsgs,
	}
}

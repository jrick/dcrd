// Copyright (c) 2023 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"

	"github.com/decred/dcrd/chaincfg/chainhash"
)

// MsgMixCM contains a partially-signed mix transaction, with signatures
// contributed from the peer identity.  When all CM messages are received,
// signatures can be merged and the transaction may be published, ending a
// successful mix session.
//
// It implements the Message interface.
type MsgMixCM struct {
	Signature [64]byte
	Identity  [33]byte
	SessionID [32]byte
	Expiry    int64
	Run       uint32
	Mix       *MsgTx
	SeenDCs   []chainhash.Hash
}

// BtcDecode decodes r using the Decred protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgMixCM) BtcDecode(r io.Reader, pver uint32) error {
	const op = "MsgMixCM.BtcDecode"
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

	if msg.Mix == nil {
		msg.Mix = NewMsgTx()
	}
	err = msg.Mix.BtcDecode(r, pver)
	if err != nil {
		return err
	}

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
	msg.SeenDCs = seen

	return nil
}

// BtcEncode encodes the receiver to w using the Decred protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgMixCM) BtcEncode(w io.Writer, pver uint32) error {
	const op = "MsgMixCM.BtcEncode"
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
func (msg *MsgMixCM) writeMessageNoSignature(op string, w io.Writer, pver uint32) error {
	err := writeElements(w, &msg.Identity, &msg.SessionID, msg.Expiry,
		msg.Run)
	if err != nil {
		return err
	}

	if msg.Mix == nil {
		msg := "nil mix transaction"
		return messageError(op, ErrInvalidMsg, msg)
	}
	err = msg.Mix.BtcEncode(w, pver)
	if err != nil {
		return err
	}

	count := len(msg.SeenDCs)
	if count > MaxPrevMixMsgs {
		msg := fmt.Sprintf("too many previous referenced messages [%v]", count)
		return messageError(op, ErrTooManyPrevMixMsgs, msg)
	}

	err = WriteVarInt(w, pver, uint64(count))
	if err != nil {
		return err
	}
	for i := range msg.SeenDCs {
		err = writeElement(w, &msg.SeenDCs[i])
		if err != nil {
			return err
		}
	}

	return nil
}

// WriteSigned writes a tag identifying the message data, followed by all
// message fields excluding the signature.  This is the data committed to when
// the message is signed.
func (msg *MsgMixCM) WriteSigned(w io.Writer) error {
	const op = "MsgMixCM.WriteSigned"

	err := WriteVarString(w, MixVersion, CmdMixCM+"-sig")
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
func (msg *MsgMixCM) Command() string {
	return CmdMixCM
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgMixCM) MaxPayloadLength(pver uint32) uint32 {
	return 16543 + MaxBlockPayloadV3
}

// Hash returns the hash of the serialized message.
func (msg *MsgMixCM) Hash() chainhash.Hash {
	return mustHash(msg, MixVersion)
}

// GetIdentity returns the message sender's public key identity.
func (msg *MsgMixCM) GetIdentity() []byte {
	return msg.Identity[:]
}

// GetSignature returns the message signature.
func (msg *MsgMixCM) GetSignature() []byte {
	return msg.Signature[:]
}

// Expires returns the block height at which the message expires.
func (msg *MsgMixCM) Expires() int64 {
	return msg.Expiry
}

// PrevMsgs returns the previous DC messages seen by the peer.
func (msg *MsgMixCM) PrevMsgs() []chainhash.Hash {
	return msg.SeenDCs
}

// Sid returns the session ID.
func (msg *MsgMixCM) Sid() []byte {
	return msg.SessionID[:]
}

// GetRun returns the run number.
func (msg *MsgMixCM) GetRun() uint32 {
	return msg.Run
}

// NewMsgMixCM returns a new mixke message that conforms to the Message
// interface using the passed parameters and defaults for the remaining fields.
func NewMsgMixCM(identity [33]byte, sid [32]byte, expiry int64, run uint32,
	mix *MsgTx, seenDCs []chainhash.Hash) *MsgMixCM {

	if mix == nil {
		mix = NewMsgTx()
	}

	return &MsgMixCM{
		Identity:  identity,
		SessionID: sid,
		Expiry:    expiry,
		Run:       run,
		Mix:       mix,
		SeenDCs:   seenDCs,
	}
}

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
	// MaxPrevMixMsgs is the maximum number previous messages of a mix run
	// that may be referenced by a message.
	MaxPrevMixMsgs = 512 // XXX: PNOOMA
)

// MsgMixKE implements the Message interface and represents a mixing key
// exchange message.  It includes a commitment to secrets (private keys and
// discarded mixed addresses) in case they must be revealed for blame
// assignment.
type MsgMixKE struct {
	Signature  [64]byte
	Identity   [33]byte
	SessionID  [32]byte
	Expiry     int64
	Run        uint32
	ECDH       [33]byte   // Secp256k1 public key
	PQPK       [1218]byte // Sntrup4591761 public key
	Commitment [32]byte
	SeenPRs    []chainhash.Hash
}

// BtcDecode decodes r using the Decred protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgMixKE) BtcDecode(r io.Reader, pver uint32) error {
	const op = "MsgMixKE.BtcDecode"
	if pver < MixVersion {
		msg := fmt.Sprintf("%s message invalid for protocol version %d",
			msg.Command(), pver)
		return messageError(op, ErrMsgInvalidForPVer, msg)
	}

	err := readElements(r, &msg.Signature, &msg.Identity, &msg.SessionID,
		&msg.Expiry, &msg.Run, &msg.ECDH, &msg.PQPK, &msg.Commitment)
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
	msg.SeenPRs = seen

	return nil
}

// BtcEncode encodes the receiver to w using the Decred protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgMixKE) BtcEncode(w io.Writer, pver uint32) error {
	const op = "MsgMixKE.BtcEncode"
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
func (msg *MsgMixKE) writeMessageNoSignature(op string, w io.Writer, pver uint32) error {
	err := writeElements(w, &msg.Identity, &msg.SessionID, msg.Expiry,
		msg.Run, &msg.ECDH, &msg.PQPK, &msg.Commitment)
	if err != nil {
		return err
	}

	// Limit to max previous messages hashes.
	count := len(msg.SeenPRs)
	if count > MaxPrevMixMsgs {
		msg := fmt.Sprintf("too many previous referenced messages [%v]", count)
		return messageError(op, ErrTooManyPrevMixMsgs, msg)
	}

	err = WriteVarInt(w, pver, uint64(count))
	if err != nil {
		return err
	}
	for i := range msg.SeenPRs {
		err := writeElement(w, &msg.SeenPRs[i])
		if err != nil {
			return err
		}
	}

	return nil
}

// WriteSigned writes a tag identifying the message data, followed by all
// message fields excluding the signature.  This is the data committed to when
// the message is signed.
func (msg *MsgMixKE) WriteSigned(w io.Writer) error {
	const op = "MsgMixKE.WriteSigned"

	err := WriteVarString(w, MixVersion, CmdMixKE+"-sig")
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
func (msg *MsgMixKE) Command() string {
	return CmdMixKE
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgMixKE) MaxPayloadLength(pver uint32) uint32 {
	return 17811
}

// Hash returns the hash of the serialized message.
func (msg *MsgMixKE) Hash() chainhash.Hash {
	return mustHash(msg, MixVersion)
}

// GetIdentity returns the message sender's public key identity.
func (msg *MsgMixKE) GetIdentity() []byte {
	return msg.Identity[:]
}

// GetSignature returns the message signature.
func (msg *MsgMixKE) GetSignature() []byte {
	return msg.Signature[:]
}

// Expires returns the block height at which the message expires.
func (msg *MsgMixKE) Expires() int64 {
	return msg.Expiry
}

// PrevMsgs returns the previous PR messages seen by the peer.
func (msg *MsgMixKE) PrevMsgs() []chainhash.Hash {
	return msg.SeenPRs
}

// Sid returns the session ID.
func (msg *MsgMixKE) Sid() []byte {
	return msg.SessionID[:]
}

// GetRun returns the run number.
func (msg *MsgMixKE) GetRun() uint32 {
	return msg.Run
}

// NewMsgMixKE returns a new mixke message that conforms to the Message
// interface using the passed parameters and defaults for the remaining fields.
func NewMsgMixKE(identity [33]byte, sid [32]byte, expires int64, run uint32,
	ecdh [33]byte, pqpk [1218]byte, commitment [32]byte, seenPRs []chainhash.Hash) *MsgMixKE {

	return &MsgMixKE{
		Identity:   identity,
		SessionID:  sid,
		Expiry:     expires,
		Run:        run,
		ECDH:       ecdh,
		PQPK:       pqpk,
		Commitment: commitment,
		SeenPRs:    seenPRs,
	}
}

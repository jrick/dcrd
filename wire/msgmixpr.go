// Copyright (c) 2023 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"fmt"
	"io"

	"github.com/decred/dcrd/chaincfg/chainhash"
)

const (
	// MaxMixPRScriptClassLen is the maximum length allowable for a
	// MsgMixPR script class.
	MaxMixPRScriptClassLen = 32

	// MaxMixPRUTXOs is the maximum number of unspent transaction outputs
	// that may be contributed in a single MixPR message.
	MaxMixPRUTXOs = 512 // XXX: PNOOMA

	// MaxMixPRUTXOScriptLen is the maximum length allowed for the unhashed
	// P2SH script of a UTXO ownership proof.
	// XXX: might want to limit this to standard script sizes
	MaxMixPRUTXOScriptLen = 16384 // txscript.MaxScriptSize

	// MaxMixPRUTXOPubKeyLen is the maximum length allowed for the
	// pubkey of a UTXO ownership proof.
	MaxMixPRUTXOPubKeyLen = 33

	// MaxMixPRUTXOSignatureLen is the maximum length allowed for the
	// signature of a UTXO ownership proof.
	MaxMixPRUTXOSignatureLen = 64
)

// MixPRUTXO describes an unspent transaction output to be spent in a mix.  It
// includes a proof that the output is able to be spent, by containing a
// signature and the necessary data needed to prove key possession.
type MixPRUTXO struct {
	OutPoint  OutPoint
	Script    []byte // Only used for P2SH
	PubKey    []byte
	Signature []byte
}

// MsgMixPR implements the Message interface and represents a mixing pair
// request message.  It describes a type of coinjoin to be created, unmixed data
// being contributed to the coinjoin, and proof of ability to sign the resulting
// coinjoin.
type MsgMixPR struct {
	Signature    [64]byte
	Identity     [33]byte
	Expiry       int64
	MixAmount    int64
	ScriptClass  string
	TxVersion    uint16
	LockTime     uint32
	MessageCount uint32
	InputValue   int64
	UTXOs        []MixPRUTXO
	Change       *TxOut
}

// Pairing returns a description of the coinjoin transaction being created.
// Different MixPR messages area compatible to perform a mix together if their
// pairing descriptions are identical.
func (msg *MsgMixPR) Pairing() ([]byte, error) {
	w := bytes.NewBuffer(make([]byte, 0, 8+32+2+4))

	err := writeElement(w, msg.MixAmount)
	if err != nil {
		return nil, err
	}

	err = WriteVarString(w, MixVersion, msg.ScriptClass)
	if err != nil {
		return nil, err
	}

	err = writeElements(w, msg.TxVersion, msg.LockTime)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// BtcDecode decodes r using the Decred protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgMixPR) BtcDecode(r io.Reader, pver uint32) error {
	const op = "MsgMixPR.BtcDecode"
	if pver < MixVersion {
		msg := fmt.Sprintf("%s message invalid for protocol version %d",
			msg.Command(), pver)
		return messageError(op, ErrMsgInvalidForPVer, msg)
	}

	err := readElements(r, &msg.Signature, &msg.Identity, &msg.Expiry,
		&msg.MixAmount)
	if err != nil {
		return err
	}

	sc, err := ReadAsciiVarString(r, pver, MaxMixPRScriptClassLen)
	if err != nil {
		return err
	}
	msg.ScriptClass = sc

	err = readElements(r, &msg.TxVersion, &msg.LockTime,
		&msg.MessageCount, &msg.InputValue)
	if err != nil {
		return err
	}

	count, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	if count > MaxMixPRUTXOs {
		msg := fmt.Sprintf("too many UTXOs in message [%v]", count)
		return messageError(op, ErrTooManyMixPRUTXOs, msg)
	}
	utxos := make([]MixPRUTXO, count)
	for i := range utxos {
		utxo := &utxos[i]

		err := ReadOutPoint(r, pver, msg.TxVersion, &utxo.OutPoint)
		if err != nil {
			return err
		}

		script, err := ReadVarBytes(r, pver, MaxMixPRUTXOScriptLen,
			"MixPRUTXO.Script")
		if err != nil {
			return err
		}
		utxo.Script = script

		pubkey, err := ReadVarBytes(r, pver, MaxMixPRUTXOPubKeyLen,
			"MixPRUTXO.PubKey")
		if err != nil {
			return err
		}
		utxo.PubKey = pubkey

		sig, err := ReadVarBytes(r, pver, MaxMixPRUTXOSignatureLen,
			"MixPRUTXO.Signature")
		if err != nil {
			return err
		}
		utxo.Signature = sig
	}
	msg.UTXOs = utxos

	var hasChange uint8
	err = readElement(r, &hasChange)
	if err != nil {
		return err
	}
	switch hasChange {
	case 0:
	case 1:
		change := new(TxOut)
		err := readTxOut(r, pver, msg.TxVersion, change)
		if err != nil {
			return err
		}
		msg.Change = change
	default:
		msg := "invalid change TxOut encoding"
		return messageError(op, ErrInvalidMsg, msg)
	}

	return nil
}

// BtcEncode encodes the receiver to w using the Decred protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgMixPR) BtcEncode(w io.Writer, pver uint32) error {
	const op = "MsgMixPR.BtcEncode"
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
func (msg *MsgMixPR) writeMessageNoSignature(op string, w io.Writer, pver uint32) error {
	err := writeElements(w, &msg.Identity, msg.Expiry, msg.MixAmount)
	if err != nil {
		return err
	}

	err = WriteVarString(w, pver, msg.ScriptClass)
	if err != nil {
		return err
	}

	err = writeElements(w, msg.TxVersion, msg.LockTime, msg.MessageCount,
		msg.InputValue)
	if err != nil {
		return err
	}

	// Limit to max UTXOs per message.
	count := len(msg.UTXOs)
	if count > MaxMixPRUTXOs {
		msg := fmt.Sprintf("too many UTXOs in message [%v]", count)
		return messageError(op, ErrTooManyMixPRUTXOs, msg)
	}

	err = WriteVarInt(w, pver, uint64(count))
	if err != nil {
		return err
	}
	for i := range msg.UTXOs {
		utxo := &msg.UTXOs[i]

		err := WriteOutPoint(w, pver, msg.TxVersion, &utxo.OutPoint)
		if err != nil {
			return err
		}

		if l := len(utxo.Script); l > MaxMixPRUTXOScriptLen {
			msg := fmt.Sprintf("UTXO script is too long [%v]", l)
			return messageError(op, ErrVarBytesTooLong, msg)
		}
		err = WriteVarBytes(w, pver, utxo.Script)
		if err != nil {
			return err
		}

		if l := len(utxo.PubKey); l > MaxMixPRUTXOPubKeyLen {
			msg := fmt.Sprintf("UTXO public key is too long [%v]", l)
			return messageError(op, ErrVarBytesTooLong, msg)
		}
		err = WriteVarBytes(w, pver, utxo.PubKey)
		if err != nil {
			return err
		}

		if l := len(utxo.Signature); l > MaxMixPRUTXOSignatureLen {
			msg := fmt.Sprintf("UTXO signature is too long [%v]", l)
			return messageError(op, ErrVarBytesTooLong, msg)
		}
		err = WriteVarBytes(w, pver, utxo.Signature)
		if err != nil {
			return err
		}
	}

	var hasChange uint8
	if msg.Change != nil {
		hasChange = 1
	}
	err = writeElement(w, hasChange)
	if err != nil {
		return err
	}
	if msg.Change != nil {
		err = writeTxOut(w, pver, msg.TxVersion, msg.Change)
		if err != nil {
			return err
		}
	}

	return nil
}

// WriteSigned writes a tag identifying the message data, followed by all
// message fields excluding the signature.  This is the data committed to when
// the message is signed.
func (msg *MsgMixPR) WriteSigned(w io.Writer) error {
	const op = "MsgMixPR.WriteSigned"

	err := WriteVarString(w, MixVersion, CmdMixPR+"-sig")
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
func (msg *MsgMixPR) Command() string {
	return CmdMixPR
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgMixPR) MaxPayloadLength(pver uint32) uint32 {
	if pver < MixVersion {
		return 0
	}

	// PR contains a transaction, and the maximum transaction
	// serialization size is limited to the max block payload.
	return MaxBlockPayload
}

// Hash returns the hash of the serialized message.
func (msg *MsgMixPR) Hash() chainhash.Hash {
	return mustHash(msg, MixVersion)
}

// GetIdentity returns the message sender's public key identity.
func (msg *MsgMixPR) GetIdentity() []byte {
	return msg.Identity[:]
}

// GetSignature returns the message signature.
func (msg *MsgMixPR) GetSignature() []byte {
	return msg.Signature[:]
}

// Expires returns the block height at which the message expires.
func (msg *MsgMixPR) Expires() int64 {
	return msg.Expiry
}

// PrevMsgs always returns nil.  Pair request messages are the initial message.
func (msg *MsgMixPR) PrevMsgs() []chainhash.Hash {
	return nil
}

// Sid always returns nil.  Pair request messages do not belong to a session.
func (msg *MsgMixPR) Sid() []byte {
	return nil
}

// GetRun always returns 0.  Pair request messages do not belong to a session.
func (msg *MsgMixPR) GetRun() uint32 {
	return 0
}

// NewMsgMixPR returns a new mixpr message that conforms to the Message
// interface using the passed parameters and defaults for the remaining fields.
func NewMsgMixPR(identity [33]byte, expiry int64, mixAmount int64,
	scriptClass string, txVersion uint16, lockTime, messageCount uint32,
	inputValue int64, utxos []MixPRUTXO, change *TxOut) (*MsgMixPR, error) {

	const op = "NewMsgMixPR"
	lenScriptClass := len(scriptClass)
	if lenScriptClass > MaxMixPRScriptClassLen {
		msg := fmt.Sprintf("script class length is too long "+
			"[len %d, max %d]", lenScriptClass,
			MaxMixPRScriptClassLen)
		return nil, messageError(op, ErrMixPRScriptClassTooLong, msg)
	}

	if !isStrictAscii(scriptClass) {
		msg := "individual initial state type is not strict ASCII"
		return nil, messageError(op, ErrMalformedStrictString, msg)
	}

	if len(utxos) > MaxMixPRUTXOs {
		msg := fmt.Sprintf("too many input UTXOs [len %d, max %d]",
			len(utxos), MaxMixPRUTXOs)
		return nil, messageError(op, ErrTooManyMixPRUTXOs, msg)
	}

	msg := &MsgMixPR{
		Identity:     identity,
		Expiry:       expiry,
		MixAmount:    mixAmount,
		ScriptClass:  scriptClass,
		TxVersion:    txVersion,
		LockTime:     lockTime,
		MessageCount: messageCount,
		InputValue:   inputValue,
		UTXOs:        utxos,
		Change:       change,
	}
	return msg, nil
}

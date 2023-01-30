// p2p: no KEs, CTs, or RM messages.
//
// Package messages implements the message types communicated between client and
// server.  The messaging in a successful run is sequenced as follows:
//
//	Client | Server
//	   PR -->       Pair Request
//	                (wait for epoch)
//	      <-- BR    Begin Run
//	   KE -->       Key Exchange
//	      <-- KEs   Server broadcasts all KE messages to all peers
//	   CT -->       Post-Quantum ciphertext exchange
//	      <-- CTs   Server broadcasts ciphertexts created by others for us
//	   SR -->       Slot Reserve
//	      <-- RM    Recovered Messages
//	   DC -->       DC-net broadcast
//	      <-- CM    Confirm Messages (unsigned)
//	   CM -->       Confirm Messages (signed)
//	                (server joins all signatures)
//	      <-- CM    Confirm Messages (with all signatures)
//
// If a peer fails to find their message after either the exponential slot
// reservation or XOR DC-net, the DC or CM message indicates to the server that
// blame must be assigned to remove malicious peers from the mix.  This process
// requires secrets committed to by the KE to be revealed.
//
//	Client | Server
//	   PR -->       Pair Request
//	                (wait for epoch)
//	      <-- BR    Begin Run
//	   KE -->       Key Exchange
//	      <-- KEs   Server broadcasts all KE messages to all peers
//	   CT -->       Post-Quantum ciphertext exchange
//	      <-- CTs   Server broadcasts ciphertexts created by others for us
//	   SR -->       Slot Reserve
//	      <-- RM    Recovered Messages
//	   DC -->       DC-net broadcast (with RevealSecrets=true)
//	      <-- CM    Confirm Messages (with RevealSecrets=true)
//	   RS -->       Reveal Secrets
//	                (server discovers misbehaving peers)
//	      <-- BR    Begin Run (with removed peers)
//	      ...
//
// At any point, if the server times out receiving a client message, the
// following message contains a nonzero BR field, and a new run is performed,
// beginning with a new key exchange.
package mixing

import (
	"crypto/ed25519"
	"encoding"
	"encoding/binary"
	"io"
	"math/big"
	"strconv"

	"decred.org/cspp/v2/x25519"
	"github.com/decred/dcrd/crypto/blake256"
)

// ServerError describes an error message sent by the server.
// The peer cannot continue in the mix session if an error is received.
// The zero value indicates the absence of an error.
type ServerError int

// Server errors
const (
	ErrAbortedSession ServerError = iota + 1
	ErrInvalidUnmixed
)

func (e ServerError) Error() string {
	switch e {
	case 0:
		return "no error"
	case ErrAbortedSession:
		return "server aborted mix session"
	case ErrInvalidUnmixed:
		return "submitted unmixed data is invalid"
	case ErrTooFewPeers:
		return "too few peers remaining to continue mix"
	default:
		return "unknown server error code " + strconv.Itoa(int(e))
	}
}

var (
	msgPR      = []byte("PR")
	msgKE      = []byte("KE")
	msgCT      = []byte("CT")
	msgSR      = []byte("SR")
	msgDC      = []byte("DC")
	msgCM      = []byte("CM")
	msgSidH    = []byte("sidH")
	msgSidHPre = []byte("sidHPre")
	msgCommit  = []byte("COMMIT")
)

func putInt(scratch []byte, v int) []byte {
	putUint64(scratch, uint64(v))
}

func putUint64(scratch []byte, v uint64) []byte {
	binary.BigEndian.PutUint64(scratch, uint64(v))
	return scratch
}

func writeSignedBigInt(w io.Writer, scratch []byte, bi *big.Int) {
	scratch[0] = byte(bi.Sign())
	w.Write(scratch[:1])
	b := bi.Bytes()
	w.Write(putInt(scratch, len(b)))
	w.Write(b)
}

func writeSlice(w io.Writer, scratch []byte, len int, write func(n int)) {
	w.Write(putInt(scratch, len))
	for i := 0; i < len; i++ {
		write(i)
	}
}

func writeSignedByteSlice(w io.Writer, scratch []byte, data []byte) {
	w.Write(putInt(scratch, len(data)))
	w.Write(data)
}

func sign(sk ed25519.PrivateKey, m Message) []byte {
	if len(sk) == 0 {
		return nil
	}
	h := blake256.New()
	m.writeSigned(h)
	return ed25519.Sign(sk, h.Sum(nil))
}

func verify(pk ed25519.PublicKey, m Message, sig []byte) bool {
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	h := blake256.New()
	m.writeSigned(h)
	return ed25519.Verify(pk, h.Sum(nil), sig)
}

type PublicKey []byte

// Message is a mixing message that, in addition to implementing the Decred wire
// protocol, also identifies previous messages of a mix session and is
// cryptographically signed by an ephimeral peer identity.
type Message interface {
	// wire.Message methods
	BtcDecode(io.Reader, uint32) error
	BtcEncode(io.Writer, uint32) error
	Command() string
	MaxPayloadLength(uint32) uint32

	writeSigned(w io.Writer)
	VerifySignature(pubkey PublicKey) bool

	isMixingMessage() // closed interface, only implemented in this package.
}

// Require these to implement Message.
var (
	_ Message = (*PR)(nil)
	_ Message = (*KE)(nil)
	_ Message = (*CT)(nil)
	_ Message = (*SR)(nil)
	_ Message = (*DC)(nil)
	_ Message = (*CM)(nil)
)

const (
	cmdMixPR = "mix-PR" // pair request
	cmdMixKE = "mix-KE" // key exchange
	cmdMixCT = "mix-CT" // pq ciphertexts
	cmdMixSR = "mix-SR" // slot reservation mix
	cmdMixDC = "mix-DC" // xor dc-net mix
	cmdMixCM = "mix-CM" // confirm a mix with our signatures
)

// XXX called by wire. would be nice to get rid of this.
func MakeEmptyMessage(command string) Message {
	var msg Message
	switch command {
	case cmdMixPR:
		msg = new(PR)
	case cmdMixKE:
		msg = new(KE)
	case cmdMixCT:
		msg = new(CT)
	case cmdMixSR:
		msg = new(SR)
	case cmdMixDC:
		msg = new(DC)
	case cmdMixCM:
		msg = new(CM)
	}

	return msg
}

// Session describes a current mixing session and run.
type Session struct {
	//sid     []byte // in p2p, session id not known until peers are grouped
	sk      PrivateKey
	vk      []PublicKey
	run     uint32
	sidH    []byte
	sidHPre []byte
}

// NewSession creates a run session from a unique session identifier and peer
// ed25519 pubkeys ordered by peer index.
// If sk is non-nil, signed message types created using this session will contain
// a valid signature.
func NewSession(sid []byte, run uint32, sk PrivateKey, vk []PublicKey) *Session {
	runBytes := putInt(make([]byte, 8), run)

	h := blake256.New()
	h.Write(msgSidH)
	h.Write(sid)
	for _, k := range vk {
		if l := len(k); l != PublicKeySize {
			panic("messages: bad ed25519 public key length: " + strconv.Itoa(l))
		}
		h.Write(k)
	}
	h.Write(runBytes)
	sidH := h.Sum(nil)

	h.Reset()
	h.Write(msgSidHPre)
	h.Write(sid)
	h.Write(runBytes)
	sidHPre := h.Sum(nil)

	return &Session{
		sid:     sid,
		sk:      sk,
		vk:      vk,
		run:     run,
		sidH:    sidH,
		sidHPre: sidHPre,
	}
}

// PR is the client's pairing request message.
// It is only seen at the start of the protocol.
type PR struct {
	Identity       PublicKey // Ephemeral session public key
	PairCommitment []byte    // Requirements for compatible mixes, e.g. same output amounts, tx versions, ...
	Unmixed        []byte    // Unmixed data contributed to a run result, e.g. transaction inputs and change outputs
	MessageCount   int       // Number of messages being mixed
	Signature      []byte
}

// PairRequest creates a signed request to be paired in a mix described by
// commitment, with possible initial unmixed data appearing in the final result.
// Ephemeral session keys pk and sk are used throughout the protocol.
func PairRequest(pk PublicKey, sk PrivateKey, commitment, unmixed []byte, mixes int) *PR {
	pr := &PR{
		Identity:       pk,
		PairCommitment: commitment,
		Unmixed:        unmixed,
		MessageCount:   mixes,
	}
	pr.Signature = sign(sk, pr)
	return pr
}

func (pr *PR) writeSigned(w io.Writer) {
	scratch := make([]byte, 8)
	w.Write(msgPR)
	writeSignedByteSlice(w, scratch, pr.Identity)
	writeSignedByteSlice(w, scratch, pr.PairCommitment)
	writeSignedByteSlice(w, scratch, pr.Unmixed)
	w.Write(putInt(scratch, pr.MessageCount))
}

func (pr *PR) VerifySignature(pub PublicKey) bool {
	return verify(pub, pr, pr.Signature)
}

/*
func () BtcDecode(r io.Reader, pver uint32) error {
}
func () BtcEncode(w io.Writer, pver uint32) error {
}
func () Command() string {
}
func () MaxPayloadLength(pver uint32) uint32 {
}
*/

func (pr *PR) BtcDecode(r io.Reader, pver uint32) error {
	return nil
}
func (pr *PR) BtcEncode(w io.Writer, pver uint32) error {
	return nil
}
func (pr *PR) Command() string {
	return "mix-PR"
}
func (pr *PR) MaxPayloadLength(pver uint32) uint32 {
	return 0
}

func (ke *KE) BtcDecode(r io.Reader, pver uint32) error {
	return nil
}
func (ke *KE) BtcEncode(w io.Writer, pver uint32) error {
	return nil
}
func (ke *KE) Command() string {
	return "mix-KE"
}
func (ke *KE) MaxPayloadLength(pver uint32) uint32 {
	return 0
}

/*
// p2p: no BR message
// BR is the begin run message.
// It is sent to all remaining valid peers when a new run begins.
type BR struct {
	Vk            []PublicKey
	MessageCounts []int
	Sid           []byte
	Err           ServerError
}

// BeginRun creates the begin run message.
func BeginRun(vk []PublicKey, mixes []int, sid []byte) *BR {
	return &BR{
		Vk:            vk,
		MessageCounts: mixes,
		Sid:           sid,
	}
}

func (br *BR) ServerError() error {
	if br.Err == 0 {
		return nil
	}
	return br.Err
}
*/

type Sntrup4591761PublicKey = [1218]byte
type Sntrup4591761Ciphertext = [1047]byte

// KE is the client's opening key exchange message of a run.
// It indicates all of the PR messages that have been observed for remaining
// peers of a compatible mix, and key material to create shared keys with all
// other peers.
type KE struct {
	Identity PublicKey
	// p2p: Validated signatures of PR messages.  Must be sorted.
	SeenPRs    [][]byte
	Run        uint32 // 0, 1, ...
	ECDH       *x25519.Public
	PQPK       *Sntrup4591761PublicKey
	Commitment []byte // Hash of RS (reveal secrets) message contents
	Signature  []byte
}

func (ke *KE) writeSigned(w io.Writer) {
	scratch := make([]byte, 8)
	w.Write(msgKE)
	writeSignedByteSlice(w, scratch, ke.Identity)
	w.Write(putInt(scratch, ke.Run))
	writeSlice(w, scratch, len(ke.SeenPRs), func(i int) {
		writeSignedByteSlice(w, scratch, ke.SeenPRs[i])
	})
	writeSignedByteSlice(w, scratch, ke.ECDH[:])
	writeSignedByteSlice(w, scratch, ke.PQPK[:])
	writeSignedByteSlice(w, scratch, ke.Commitment)
}

func (ke *KE) VerifySignature(pub PublicKey) bool {
	return verify(pub, ke, ke.Signature)
}

func (ke *KE) Sid() []byte {
	h := blake256.New()
	for i := range ke.SeenPRs {
		h.Write(ke.SeenPRs[i])
	}
	return h.Sum(nil)
}

// KeyExchange creates a signed key exchange message to verifiably provide the
// x25519 and sntrup4591761 public keys.
func KeyExchange(kx *KX, commitment []byte, ses *Session) *KE {
	ke := &KE{
		Run:        ses.run,
		ECDH:       &kx.X25519.Public,
		PQPK:       kx.PQPublic,
		Commitment: commitment,
	}
	ke.Signature = sign(ses.sk, ke)
	return ke
}

// CT is the client's exchange of post-quantum shared key ciphertexts with all
// other peers in the run.
type CT struct {
	Ciphertexts []*Sntrup4591761Ciphertext
	Signature   []byte
}

func (ct *CT) writeSigned(w io.Writer) {
	scratch := make([]byte, 8)
	w.Write(msgCT)
	w.Write(putInt(scratch, len(ct.Ciphertexts)))
	for _, ciphertext := range ct.Ciphertexts {
		var ct []byte
		if ciphertext != nil {
			ct = ciphertext[:]
		}
		writeSignedByteSlice(w, scratch, ct)
	}
}

func (ct *CT) VerifySignature(pub PublicKey) bool {
	return verify(pub, ct, ct.Signature)
}

// Ciphertexts creates the ciphertext message.
func Ciphertexts(ciphertexts []*Sntrup4591761Ciphertext, ses *Session) *CT {
	ct := &CT{
		Ciphertexts: ciphertexts,
	}
	ct.Signature = sign(ses.sk, ct)
	return ct
}

// SR is the slot reservation broadcast.
type SR struct {
	Run       uint32
	DCMix     [][]*big.Int
	Signature []byte
}

func (sr *SR) writeSigned(w io.Writer) {
	scratch := make([]byte, 8)
	w.Write(msgSR)
	w.Write(putInt(scratch, sr.Run))
	w.Write(putInt(scratch, len(sr.DCMix)))
	for i := range sr.DCMix {
		writeSlice(w, scratch, len(sr.DCMix[i]), func(j int) {
			writeSignedBigInt(w, scratch, sr.DCMix[i][j])
		})
	}
}

func (sr *SR) VerifySignature(pub PublicKey) bool {
	return verify(pub, sr, sr.Signature)
}

// SlotReserve creates a slot reservation message to discover random, anonymous
// slot assignments for an XOR DC-net by mixing random data in a exponential
// DC-mix.
func SlotReserve(dcmix [][]*big.Int, s *Session) *SR {
	sr := &SR{
		Run:   s.run,
		DCMix: dcmix,
	}
	sr.Signature = sign(s.sk, sr)
	return sr
}

/*
// RM is the recovered messages result of collecting all SR messages and solving for
// the mixed original messages.
type RM struct {
	Run           uint32
	Roots         []*big.Int
	RevealSecrets bool
}

// RecoveredMessages creates a recovered messages message.
func RecoveredMessages(roots []*big.Int, s *Session) *RM {
	return &RM{
		Run:   s.run,
		Roots: roots,
	}
}
*/

// DC is the DC-net broadcast.
type DC struct {
	Run           uint32
	DCNet         []*Vec
	RevealSecrets bool
	Signature     []byte
}

func (dc *DC) writeSigned(w io.Writer) {
	scratch := make([]byte, 8)
	w.Write(msgDC)
	w.Write(putInt(scratch, dc.Run))
	writeSlice(w, scratch, len(dc.DCNet), func(i int) {
		w.Write(putInt(scratch, dc.DCNet[i].N))
		w.Write(putInt(scratch, dc.DCNet[i].Msize))
		w.Write(dc.DCNet[i].Data)
	})
	var rs byte
	if dc.RevealSecrets {
		rs = 1
	}
	scratch[0] = rs
	w.Write(scratch[:1])
}

func (dc *DC) VerifySignature(pub PublicKey) bool {
	return verify(pub, dc, dc.Signature)
}

// DCNet creates a message containing the previously-committed DC-mix vector and
// the shared keys of peers we have chosen to exclude.
func DCNet(dcs []*Vec, s *Session) *DC {
	dc := &DC{
		Run:   s.run,
		DCNet: dcs,
	}
	dc.Signature = sign(s.sk, dc)
	return dc
}

// CM is the confirm mix message.  Each peer signs their contributed inputs and
// broadcasts the partially-signed transaction.
type CM struct {
	Mix           *wire.MsgTx
	RevealSecrets bool
	Signature     []byte
}

func (cm *CM) writeSigned(w io.Writer) {
	w.Write(msgCM)
	// Only the RevealSecrets field must be signed by clients, as Mix
	// already contains signatures, and RevealSecrets is the only other data
	// sent by clients in this message.
	var rs byte
	if cm.RevealSecrets {
		rs = 1
	}
	w.Write([]byte{rs})
}

func (cm *CM) VerifySignature(pub PublicKey) bool {
	return verify(pub, cm, cm.Signature)
}

// ConfirmMix creates the confirm mix message.
func ConfirmMix(sk PrivateKey, mix BinaryRepresentable) *CM {
	cm := &CM{Mix: mix}
	cm.Signature = sign(sk, cm)
	return cm
}

// RS is the reveal secrets message.  It reveals a run's PRNG seed, SR
// and DC secrets at the end of a failed run for blame assignment and
// misbehaving peer removal.
type RS struct {
	Seed []byte
	SR   []*big.Int
	M    [][]byte
}

// RevealSecrets creates the reveal secrets message.
func RevealSecrets(prngSeed []byte, sr []*big.Int, m [][]byte, s *Session) *RS {
	rs := &RS{
		Seed: prngSeed,
		SR:   sr,
		M:    m,
	}

	return rs
}

// Commit commits to the contents of the reveal secrets message.
func (rs *RS) Commit(ses *Session) []byte {
	scratch := make([]byte, 8)
	h := blake256.New()
	h.Write(msgCommit)
	h.Write(ses.sid)
	binary.LittleEndian.PutUint32(scratch, uint32(ses.run))
	h.Write(scratch)
	writeSignedByteSlice(h, scratch, rs.Seed)
	writeSlice(h, scratch, len(rs.SR), func(j int) {
		writeSignedBigInt(h, scratch, rs.SR[j])
	})
	writeSlice(h, scratch, len(rs.M), func(j int) {
		writeSignedByteSlice(h, scratch, rs.M[j])
	})
	return h.Sum(nil)
}

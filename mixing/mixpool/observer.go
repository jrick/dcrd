// Copyright (c) 2024 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mixpool

import (
	"context"
	"sync"
	"time"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/wire"
)

const strikeLimit = 2

const minPeers = 4 // Keep synced with mixclient.MinPeers

// Observer tracks outpoints that were not included in successful mixes.  This
// provides mempool and voting policy the context necessary to discourage
// denial-of-service where misbehaving mixing peers churn and resubmit
// disruptive pair requests.
type Observer struct {
	mixpool *Pool
	epoch   time.Duration
	strikes map[wire.OutPoint][]uint64
	mu      sync.RWMutex
}

// NewObserver creates an observer client watching the mixpool.
func NewObserver(mixpool *Pool) *Observer {
	o := &Observer{
		mixpool: mixpool,
		epoch:   mixpool.Epoch(),
		strikes: make(map[wire.OutPoint][]uint64),
	}
	mixpool.observer = o
	return o
}

// waitForEpoch blocks until the next epoch, or errors when the context is
// cancelled early.  Returns the calculated epoch.
func (o *Observer) waitForEpoch(ctx context.Context) (uint64, error) {
	now := time.Now().UTC()
	epoch := now.Truncate(o.epoch).Add(o.epoch)
	epochUnix := uint64(epoch.Unix())
	duration := epoch.Sub(now)
	timer := time.NewTimer(duration)
	select {
	case <-ctx.Done():
		if !timer.Stop() {
			<-timer.C
		}
		return epochUnix, ctx.Err()
	case <-timer.C:
		return epochUnix, nil
	}
}

// Run waits for every epoch to complete before checking for misbehavior in
// the previous epoch.
func (o *Observer) Run(ctx context.Context) error {
	// A pre-cancelled context is used to receive mixpool messages without
	// waiting for a particular count of messages.
	cancelledCtx, cancel := context.WithCancel(ctx)
	cancel()

	// Track the previous epoch (as Unix time).  Sessions are particular
	// to the epoch they were formed under, and only messages from the
	// previous finished epoch are considered by the observer.
	var prevEpoch uint64

	for {
		epoch, err := o.waitForEpoch(ctx)
		if err != nil {
			return err
		}
		if prevEpoch == 0 {
			prevEpoch = epoch
			continue
		}

		err = o.checkPrevEpoch(cancelledCtx, prevEpoch)
		if err != nil {
			return err
		}

		prevEpoch = epoch
	}
}

// CheckPrevEpoch checks for timeout misbehavior in the previous epoch.
func (o *Observer) CheckPrevEpoch(prevEpoch uint64) error {
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	return o.checkPrevEpoch(cancelledCtx, prevEpoch)
}

func (o *Observer) checkPrevEpoch(cancelledCtx context.Context, prevEpoch uint64) error {
	// Gather all attempted session formations, and those sessions
	// which ended in a pairings mix (number of received
	// confirmation messages equals the number of session
	// participants).
	//
	// The pairings variable maps all pairing IDs -> session hash -> KEs;
	// completed maps only completed pairing IDs -> KEs.
	pairings := make(map[string]map[chainhash.Hash][]*wire.MsgMixKeyExchange)
	completed := make(map[string][]*wire.MsgMixKeyExchange)
	prByKE := make(map[chainhash.Hash]*wire.MsgMixPairReq)
	timedOut := make(map[string]map[idPubKey]struct{})
	active := o.mixpool.activeInEpoch(prevEpoch)
	for _, a := range active {
		pairing, err := a.pr.Pairing()
		if err != nil {
			return err
		}
		ses := pairings[string(pairing)]
		if ses == nil {
			ses = make(map[chainhash.Hash][]*wire.MsgMixKeyExchange)
			pairings[string(pairing)] = ses
		}
		for _, ke := range a.kes {
			ses[ke.SessionID] = append(ses[ke.SessionID], ke)
			prByKE[ke.Hash()] = a.pr
		}
	}
	r := &Received{
		ReceiveAll: true,
	}
	for _, ses := range pairings {
		for sid, sesKEs := range ses {
			// Sessions formed with fewer than the
			// required minimum peer count can't be used
			// to discover misbehavior.
			if len(sesKEs) < minPeers {
				continue
			}

			r.Sid = sid
			// Capacity must be > 0 in order to receive messages.
			// Capacity does not limit the number of messages initially
			// read with a cancelled context.
			// Receiving into multiple result slices is allowed with
			// ReceiveAll = true.
			if cap(r.CTs) == 0 {
				r.CTs = make([]*wire.MsgMixCiphertexts, 0, len(sesKEs))
				r.SRs = make([]*wire.MsgMixSlotReserve, 0, len(sesKEs))
				r.DCs = make([]*wire.MsgMixDCNet, 0, len(sesKEs))
				r.CMs = make([]*wire.MsgMixConfirm, 0, len(sesKEs))
				r.RSs = make([]*wire.MsgMixSecrets, 0, len(sesKEs))
			} else {
				r.CTs = r.CTs[:0]
				r.SRs = r.SRs[:0]
				r.DCs = r.DCs[:0]
				r.CMs = r.CMs[:0]
				r.RSs = r.RSs[:0]
			}
			_ = o.mixpool.Receive(cancelledCtx, r)

			if len(r.RSs) > 0 {
				continue
			}

			pairing, err := prByKE[sesKEs[0].Hash()].Pairing()
			if err != nil {
				return err
			}
			if len(r.CMs) == len(sesKEs) {
				completed[string(pairing)] = sesKEs
				continue
			}

			// If a session was fully formed (all KEs received by each peer),
			// but later messages in the protocol were never received, peers
			// may have intentionally timed out.
			if len(sesKEs[0].SeenPRs) != len(sesKEs) {
				continue
			}
			ids := make(map[idPubKey]struct{})
			for _, ke := range sesKEs {
				ids[ke.Identity] = struct{}{}
			}
			switch {
			case len(r.CTs) < len(sesKEs):
				for _, ct := range r.CTs {
					delete(ids, ct.Identity)
				}
			case len(r.SRs) < len(sesKEs):
				for _, sr := range r.SRs {
					delete(ids, sr.Identity)
				}
			case len(r.DCs) < len(sesKEs):
				for _, dc := range r.DCs {
					delete(ids, dc.Identity)
				}
			case len(r.CMs) < len(sesKEs):
				for _, cm := range r.CMs {
					delete(ids, cm.Identity)
				}
			}
			if _, ok := timedOut[string(pairing)]; !ok {
				timedOut[string(pairing)] = make(map[idPubKey]struct{})
			}
			for id := range ids {
				timedOut[string(pairing)][id] = struct{}{}
			}
		}
	}

	// Modify the active map by removing identities that were
	// included in a completed mix.  Those remaining who sent key
	// exchange messages but who (for any reason) were not
	// included in a completed mix are assumed to be misbehaving
	// and trying to disrupt mixing, and restrictions on their
	// submitted UTXOs will be put in place after too many
	// violations.
	for _, kes := range completed {
		for _, ke := range kes {
			delete(active, ke.Identity)
		}
	}

	// Modify the active map by removing identities when no
	// successful mix occurred for the pairing.  If any peers
	// timed out for the pairing, do not exclude them from the
	// misbehaving peer set if they were discovered to have timed
	// out.
	for id, ap := range active {
		// Active peers will always have at least one KE, and
		// all KEs must be for the same pairing type.
		pairing, err := prByKE[ap.kes[0].Hash()].Pairing()
		if err != nil {
			return err
		}
		if _, ok := completed[string(pairing)]; !ok {
			if timedOutIDs, ok := timedOut[string(pairing)]; ok {
				if _, ok := timedOutIDs[id]; ok {
					continue
				}
			}
			delete(active, id)
		}
	}

	o.updateStrikes(prevEpoch, active, prByKE, completed)

	return nil
}

func (o *Observer) updateStrikes(epoch uint64, misbehaving map[idPubKey]activePeer,
	prByKE map[chainhash.Hash]*wire.MsgMixPairReq,
	completed map[string][]*wire.MsgMixKeyExchange) {

	o.mu.Lock()
	defer o.mu.Unlock()

	// Add a strike for any active identity that was not included in a
	// completed mix last epoch.
	for _, ap := range misbehaving {
		log.Debugf("Pair request by mixing identity %x flagged for misbehavior",
			ap.pr.Identity[:])
		for i := range ap.pr.UTXOs {
			outpoint := &ap.pr.UTXOs[i].OutPoint
			o.strikes[*outpoint] = append(o.strikes[*outpoint], epoch)
		}
	}

	// Remove strikes for UTXOs spent by completed mixes.
	for _, kes := range completed {
		for _, ke := range kes {
			pr := prByKE[ke.Hash()]
			for i := range pr.UTXOs {
				outpoint := &pr.UTXOs[i].OutPoint
				delete(o.strikes, *outpoint)
			}
		}
	}

	// Remove strikes if none occurred in the past 24h.
	cutoff := epoch - (60 * 60 * 24)
	for op, strikes := range o.strikes {
		if strikes[len(strikes)-1] <= cutoff {
			delete(o.strikes, op)
		}
	}
}

func (o *Observer) removeStrikesForMix(tx *wire.MsgTx) {
	o.mu.Lock()
	defer o.mu.Unlock()

	for _, in := range tx.TxIn {
		delete(o.strikes, in.PreviousOutPoint)
	}
}

// MisbehavingBlock returns whether any transaction in the block spends an
// output that was flagged as submitted by a misbehaving mixing peer.
func (o *Observer) MisbehavingBlock(block *wire.MsgBlock) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()

	for _, tx := range block.Transactions {
		if o.misbehavingTx(tx, block) {
			return true
		}
	}
	for _, tx := range block.STransactions {
		if o.misbehavingTx(tx, block) {
			return true
		}
	}
	return false
}

// MisbehavingTx returns whether any transaction output was flagged as
// submitted by a misbehaving mixing peer.
func (o *Observer) MisbehavingTx(tx *wire.MsgTx) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()

	return o.misbehavingTx(tx, nil)
}

func (o *Observer) misbehavingTx(tx *wire.MsgTx, block *wire.MsgBlock) bool {
	for _, in := range tx.TxIn {
		if len(o.strikes[in.PreviousOutPoint]) >= strikeLimit {
			if block == nil {
				log.Debugf("Transaction %v spends misbehaving mixing input %v",
					tx.TxHash(), in.PreviousOutPoint)
			} else {
				log.Debugf("Transaction %v in block %v spends misbehaving mixing input %v",
					tx.TxHash(), block.Header.BlockHash(), in.PreviousOutPoint)
			}
			return true
		}
	}
	return false
}

// ExcludePRs returns a slice of pair request messages excluding any which
// spend previously-flagged misbehaving outputs.
func (o *Observer) ExcludePRs(prs []*wire.MsgMixPairReq) []*wire.MsgMixPairReq {
	o.mu.RLock()
	defer o.mu.RUnlock()

	l := len(prs)
	prs = prs[:0]
	for _, pr := range prs[:l] {
		for i := range pr.UTXOs {
			if len(o.strikes[pr.UTXOs[i].OutPoint]) >= strikeLimit {
				continue
			}
		}
		prs = append(prs, pr)
	}
	return prs
}

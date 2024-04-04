// Copyright (c) 2024 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
)

// Determine if systemd allocated file descriptors for peer-to-peer network
// and RPC listeners.
func init() {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) {
		return
	}

	numFDs, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid LISTEN_FDS:", err)
		os.Exit(1)
	}

	switch numFDs {
	case 1, 2:
	default:
		fmt.Fprintf(os.Stderr, "LISTEN_FDS expected to be 1 or 2, got %d\n", numFDs)
		os.Exit(1)
	}

	for i := 0; i < numFDs; i++ {
		fd := uintptr(i + 3) // Passed file descriptors begin at 3.
		f := os.NewFile(fd, fmt.Sprintf("_%d (from systemd)", fd))
		l, err := net.FileListener(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot listen on file from systemd fd %d: %v\n", fd, err)
			os.Exit(1)
		}
		switch fd {
		case 3:
			inheritedListeners.p2pListener = l
		case 4:
			inheritedListeners.rpcListener = l
		}
	}
}

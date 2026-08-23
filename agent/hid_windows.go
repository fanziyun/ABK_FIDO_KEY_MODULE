//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
)

// vhidPipe is the contract between this agent and a Windows virtual-HID
// backend: whoever serves the pipe must accept 64-byte CTAP reports written by
// the host and hand back 64-byte device replies, framed exactly like the Linux
// uhid path. Windows has no in-box equivalent of /dev/uhid, and browsers there
// reach a security key through the Windows WebAuthn stack, which enumerates
// real HID devices only, so the LAN relay cannot work on Windows until such a
// backend (a signed HID minidriver plus its user-mode service) is installed.
// None ships with this project yet.
const vhidPipe = `\\.\pipe\abk-fido-vhid`

type windowsHID struct{ f *os.File }

// checkHIDBackend runs before discovery and pairing so a missing backend is
// reported as the setup problem it is, instead of surfacing a bare
// ERROR_FILE_NOT_FOUND after the user has already read a pairing code off the
// phone.
func checkHIDBackend() error {
	f, err := os.OpenFile(vhidPipe, os.O_RDWR, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf(`no virtual HID backend is listening on %s.

Windows browsers only see a security key through a real HID device, and this
project does not ship the HID minidriver that would serve that pipe, so the LAN
relay has nothing to attach to. Use one of these instead:
  * connect the phone over USB - the gadget is a native FIDO HID key there and
    Windows needs no driver for it;
  * run the agent on Linux, where /dev/uhid provides the virtual key;
  * install a virtual-HID backend that serves %s and start it first.`,
				vhidPipe, vhidPipe)
		}
		return err
	}
	return f.Close()
}

func NewHID(device string) (HID, error) {
	if device == "" {
		device = vhidPipe
	}
	f, err := os.OpenFile(device, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return &windowsHID{f: f}, nil
}
func (h *windowsHID) Read() ([]byte, error) {
	p := make([]byte, reportLen)
	_, e := io.ReadFull(h.f, p)
	return p, e
}
func (h *windowsHID) Write(p []byte) error {
	if len(p) != reportLen {
		return errors.New("invalid HID packet")
	}
	_, e := h.f.Write(p)
	return e
}
func (h *windowsHID) Close() error { return h.f.Close() }

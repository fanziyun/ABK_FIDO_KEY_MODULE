//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"
)

// syscall does not name this one, and the agent has no third-party dependencies
// to borrow it from.
const errorSharingViolation = syscall.Errno(32)

// vhidDevice is the control device that windows/vhid/abkfidovhid.sys exposes.
// The driver is a KMDF function driver over the Virtual HID Framework: reports
// this agent writes here are submitted to the HID stack as device-to-host input
// reports, and host-to-device output reports arrive as reads - the same 64-byte
// CTAP framing the Linux /dev/uhid path uses.
//
// Its security descriptor only admits SYSTEM and Administrators, so the agent
// has to run elevated.
const vhidDevice = `\\.\ABKFidoVhid`

// installHint points at the packaged installer rather than describing the
// SetupAPI dance, because the devnode also needs a trusted certificate and test
// signing, and Install-AbkFidoVhid.ps1 checks all three.
const installHint = `Install the virtual HID driver first: from an elevated PowerShell prompt, run
.\Install-AbkFidoVhid.ps1 in the abk-fido-vhid package (the "Build Windows
Virtual HID Driver" workflow artifact). The package is self-signed, so the
machine also needs test signing on (bcdedit /set testsigning on), which requires
Secure Boot to be disabled. Run .\abkvhidctl.exe status to see where it stands.

Alternatively, connect the phone over USB: it is a native FIDO HID key there and
needs no driver on Windows.`

type windowsHID struct{ f *os.File }

// checkHIDBackend runs before discovery and pairing so a missing or unusable
// driver is reported as the setup problem it is, instead of surfacing a bare
// ERROR_FILE_NOT_FOUND after the user has already read a pairing code off the
// phone.
func checkHIDBackend() error {
	f, err := os.OpenFile(vhidDevice, os.O_RDWR, 0)
	if err != nil {
		return describeOpenError(err)
	}
	return f.Close()
}

func describeOpenError(err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%s does not exist.\n\n%s", vhidDevice, installHint)
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("%s refused access: the agent has to run elevated (try `sudo` or an "+
			"administrator prompt).", vhidDevice)
	case errors.Is(err, errorSharingViolation):
		return fmt.Errorf("%s is already open: the driver admits one client at a time, so another "+
			"agent is still running.", vhidDevice)
	}
	return err
}

func NewHID(device string) (HID, error) {
	if device == "" {
		device = vhidDevice
	}
	f, err := os.OpenFile(device, os.O_RDWR, 0)
	if err != nil {
		return nil, describeOpenError(err)
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

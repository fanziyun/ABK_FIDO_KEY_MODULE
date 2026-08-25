//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"
	"unsafe"
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

// abkIoctlGetStats is CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED,
// FILE_READ_DATA), matching ABK_IOCTL_GET_STATS in windows/vhid.
const abkIoctlGetStats = (0x22 << 16) | (1 << 14) | (0x800 << 2)

type abkStats struct {
	Size              uint32
	HostReports       uint32
	LastHostReportLen uint32
	Submitted         uint32
	SubmitFailures    uint32
	LastSubmitStatus  uint32
	LastSubmitLen     uint32
	GetInputReports   uint32
	GetInputServed    uint32
	ReplyBacklog      uint32
	Dropped           uint32
}

// Stats asks the driver what the HID stack has actually done. A host that never
// reads our replies looks identical from up here to one that reads and rejects
// them; these counters are the difference.
func (h *windowsHID) Stats() (string, error) {
	var (
		s   abkStats
		got uint32
	)
	buf := (*byte)(unsafe.Pointer(&s))
	err := syscall.DeviceIoControl(syscall.Handle(h.f.Fd()), abkIoctlGetStats,
		nil, 0, buf, uint32(unsafe.Sizeof(s)), &got, nil)
	if err != nil {
		return "", err
	}
	if got < uint32(unsafe.Sizeof(s)) {
		return "", fmt.Errorf("short stats buffer (%d bytes)", got)
	}
	return fmt.Sprintf("vhid stats: host_reports=%d last_host_len=%d submitted=%d "+
		"submit_failures=%d last_submit=0x%08x/%d get_input=%d served=%d backlog=%d dropped=%d",
		s.HostReports, s.LastHostReportLen, s.Submitted, s.SubmitFailures,
		s.LastSubmitStatus, s.LastSubmitLen, s.GetInputReports, s.GetInputServed,
		s.ReplyBacklog, s.Dropped), nil
}

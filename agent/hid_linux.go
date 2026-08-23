//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"os"
)

// Linux UHID event constants and the fixed-size create/input/output events.
const (
	uhidCreate2      = 11
	uhidInput2       = 12
	uhidOutput       = 6
	uhidOutputReport = 1
	uhidStart        = 3
	uhidDestroy      = 1
)

type linuxHID struct{ f *os.File }

func NewHID(device string) (HID, error) {
	u, err := os.OpenFile("/dev/uhid", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	h := &linuxHID{f: u}
	if _, err = u.Write(buildUHIDCreate2()); err != nil {
		u.Close()
		return nil, err
	}
	return h, nil
}

// UHID identity of the virtual key. uhid_create2_req stores the ids in u32
// fields, but a HID vendor/product id is 16 bits everywhere else: the kernel
// publishes them as `HID_ID=bus:vendor:product` in the hidraw uevent, and
// Chromium (so Edge and Chrome) refuses to enumerate a hidraw node whose
// HID_ID components do not fit in a u16. A wider value makes the device
// invisible to every browser while libfido2, which truncates instead, keeps
// working — exactly the split we saw with product 0xF1D02.
const (
	uhidVendorID  = 0xABCD
	uhidProductID = 0x1D02
)

func buildUHIDCreate2() []byte {
	name := [128]byte{}
	copy(name[:], []byte("ABK FIDO2 Security Key"))
	rd := []byte{0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0, 0x26, 0xff, 0, 0x75, 8, 0x95, 0x40, 0x81, 2, 0x09, 0x21, 0x15, 0, 0x26, 0xff, 0, 0x75, 8, 0x95, 0x40, 0x91, 2, 0xc0}
	// struct uhid_event { u32 type; union { struct uhid_create2_req create2; } }.
	b := make([]byte, 4+4372)
	binary.LittleEndian.PutUint32(b, uhidCreate2)
	copy(b[4:], name[:])
	binary.LittleEndian.PutUint16(b[4+256:], uint16(len(rd)))
	binary.LittleEndian.PutUint16(b[4+258:], 0x03)
	binary.LittleEndian.PutUint32(b[4+260:], uhidVendorID)
	binary.LittleEndian.PutUint32(b[4+264:], uhidProductID)
	binary.LittleEndian.PutUint32(b[4+268:], 1)
	copy(b[4+276:], rd)
	return b
}
func (h *linuxHID) Close() error { return h.f.Close() }
func (h *linuxHID) Read() ([]byte, error) {
	b := make([]byte, 4380)
	for {
		n, e := h.f.Read(b)
		if e != nil {
			return nil, e
		}
		packet, ready, err := parseUHIDOutput(b[:n])
		if err != nil {
			return nil, err
		}
		// UHID emits lifecycle/control events (most notably UHID_START) before
		// the first output report. They are normal and must not terminate the
		// relay reader; keep consuming events until the host sends a report.
		if ready {
			return packet, nil
		}
	}
}

// parseUHIDOutput extracts a complete 64-byte host output report. It returns
// ready=false for valid non-output UHID events, which callers should ignore.
//
// hidraw keeps the report-number byte that userspace prepends (0x00 for a
// device whose reports are unnumbered, which is what CTAP HID uses) and the HID
// core forwards the buffer to uhid untouched, so a 64-byte CTAP frame arrives
// here as 65 bytes. Strip that prefix; without it every relayed frame is
// shifted by one byte and the authenticator sees garbage.
func parseUHIDOutput(event []byte) ([]byte, bool, error) {
	if len(event) < 4 {
		return nil, false, fmt.Errorf("short UHID event")
	}
	if binary.LittleEndian.Uint32(event) != uint32(uhidOutput) {
		return nil, false, nil
	}
	// struct uhid_output_req is { data[4096], size, rtype } and follows the
	// four-byte event type. The report length is stored at offset 4100.
	const sizeOffset = 4 + 4096
	if len(event) < sizeOffset+2 {
		return nil, false, fmt.Errorf("short UHID output event")
	}
	size := int(binary.LittleEndian.Uint16(event[sizeOffset:]))
	if len(event) < sizeOffset+3 || event[sizeOffset+2] != uhidOutputReport {
		return nil, false, nil
	}
	data := event[4:]
	if size > len(data) {
		return nil, false, fmt.Errorf("UHID output size %d exceeds event", size)
	}
	if size > reportLen && data[0] == 0 {
		data = data[1:]
		size--
	}
	if size < reportLen {
		return nil, false, fmt.Errorf("short HID output: %d", size)
	}
	return append([]byte(nil), data[:reportLen]...), true, nil
}
func (h *linuxHID) Write(p []byte) error {
	if len(p) != reportLen {
		return fmt.Errorf("invalid HID packet length: %d", len(p))
	}
	// Input reports carry no report-number prefix: the device is unnumbered, so
	// the host expects exactly the 64 CTAP bytes.
	b := make([]byte, 4+2+4096)
	binary.LittleEndian.PutUint32(b, uint32(uhidInput2))
	binary.LittleEndian.PutUint16(b[4:6], uint16(len(p)))
	copy(b[6:], p)
	_, e := h.f.Write(b)
	return e
}

//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestParseUHIDOutputSkipsLifecycleEvent(t *testing.T) {
	event := make([]byte, 4380)
	binary.LittleEndian.PutUint32(event, uint32(uhidStart))
	packet, ready, err := parseUHIDOutput(event)
	if err != nil || ready || packet != nil {
		t.Fatalf("lifecycle event: packet=%x ready=%v err=%v", packet, ready, err)
	}
}

func TestParseUHIDOutputReturnsReport(t *testing.T) {
	event := make([]byte, 4380)
	binary.LittleEndian.PutUint32(event, uint32(uhidOutput))
	for i := 0; i < 64; i++ {
		event[4+i] = byte(i)
	}
	binary.LittleEndian.PutUint16(event[4+4096:], 64)
	event[4+4096+2] = uhidOutputReport
	packet, ready, err := parseUHIDOutput(event)
	if err != nil || !ready || len(packet) != 64 {
		t.Fatalf("output event: packet=%x ready=%v err=%v", packet, ready, err)
	}
	for i, b := range packet {
		if b != byte(i) {
			t.Fatalf("packet[%d]=%d", i, b)
		}
	}
}

func TestParseUHIDOutputRejectsShortReport(t *testing.T) {
	event := make([]byte, 4380)
	binary.LittleEndian.PutUint32(event, uint32(uhidOutput))
	binary.LittleEndian.PutUint16(event[4+4096:], 63)
	event[4+4096+2] = uhidOutputReport
	if _, ready, err := parseUHIDOutput(event); err == nil || ready {
		t.Fatalf("expected short report error, ready=%v err=%v", ready, err)
	}
}

// hidraw keeps the report-number byte userspace prepends, so a 64-byte CTAP
// frame reaches uhid as 65 bytes led by 0x00. libfido2 and Chromium both write
// that way, and keeping the prefix shifts every relayed frame by one byte.
func TestParseUHIDOutputStripsReportNumber(t *testing.T) {
	event := make([]byte, 4380)
	binary.LittleEndian.PutUint32(event, uint32(uhidOutput))
	event[4] = 0x00
	for i := 0; i < 64; i++ {
		event[5+i] = byte(i)
	}
	binary.LittleEndian.PutUint16(event[4+4096:], 65)
	event[4+4096+2] = uhidOutputReport
	packet, ready, err := parseUHIDOutput(event)
	if err != nil || !ready || len(packet) != 64 {
		t.Fatalf("numbered report: packet=%x ready=%v err=%v", packet, ready, err)
	}
	for i, b := range packet {
		if b != byte(i) {
			t.Fatalf("packet[%d]=%d want %d", i, b, i)
		}
	}
}

// A CTAP INIT frame must survive intact; before the prefix was stripped it
// arrived as 00 ff ff ff ff and the phone rejected the bogus length.
func TestParseUHIDOutputPreservesInitFrame(t *testing.T) {
	frame := make([]byte, 64)
	copy(frame, []byte{0xff, 0xff, 0xff, 0xff, 0x86, 0x00, 0x08})
	event := make([]byte, 4380)
	binary.LittleEndian.PutUint32(event, uint32(uhidOutput))
	copy(event[5:], frame)
	binary.LittleEndian.PutUint16(event[4+4096:], 65)
	event[4+4096+2] = uhidOutputReport
	packet, ready, err := parseUHIDOutput(event)
	if err != nil || !ready {
		t.Fatalf("init frame: ready=%v err=%v", ready, err)
	}
	if !bytes.Equal(packet, frame) {
		t.Fatalf("init frame corrupted: got %x", packet[:8])
	}
}

func TestParseUHIDOutputRejectsOversizedSize(t *testing.T) {
	event := make([]byte, 4380)
	binary.LittleEndian.PutUint32(event, uint32(uhidOutput))
	binary.LittleEndian.PutUint16(event[4+4096:], 5000)
	event[4+4096+2] = uhidOutputReport
	if _, ready, err := parseUHIDOutput(event); err == nil || ready {
		t.Fatalf("expected oversized size error, ready=%v err=%v", ready, err)
	}
}

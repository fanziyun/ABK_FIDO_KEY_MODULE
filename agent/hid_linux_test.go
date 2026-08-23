//go:build linux

package main

import (
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

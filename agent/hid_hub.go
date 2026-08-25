package main

import (
	"encoding/binary"
	"errors"
	"log"
	"sync"
)

var errHIDSessionSuperseded = errors.New("HID session superseded")

type hidSubscription struct {
	packets chan []byte
	done    chan struct{}
	once    sync.Once
}

func (s *hidSubscription) close() {
	s.once.Do(func() { close(s.done) })
}

// hidHub owns the single UHID reader. A session subscribes only while it has
// an authenticated LAN connection, so a dropped connection cannot leave a
// second reader consuming reports intended for a later session.
type hidHub struct {
	hid HID

	mu      sync.Mutex
	active  *hidSubscription
	pending [][]byte
}

func newHIDHub(hid HID) *hidHub { return &hidHub{hid: hid} }

func (h *hidHub) subscribe() *hidSubscription {
	s := &hidSubscription{packets: make(chan []byte, maxPendingPackets), done: make(chan struct{})}
	h.mu.Lock()
	previous := h.active
	h.active = s
	pending := h.pending
	h.pending = nil
	h.mu.Unlock()
	if previous != nil {
		previous.close()
	}
	for _, packet := range pending {
		select {
		case s.packets <- packet:
		case <-s.done:
			return s
		}
	}
	return s
}

func (h *hidHub) unsubscribe(s *hidSubscription) {
	h.mu.Lock()
	if h.active == s {
		h.active = nil
	}
	h.mu.Unlock()
	s.close()
}

func (h *hidHub) run() error {
	for {
		packet, err := h.hid.Read()
		if err != nil {
			h.mu.Lock()
			active := h.active
			h.active = nil
			h.mu.Unlock()
			if active != nil {
				active.close()
			}
			return err
		}
		if len(packet) != 64 {
			continue
		}
		logHostFrame(packet)

		h.mu.Lock()
		active := h.active
		if active == nil {
			if len(h.pending) < maxPendingPackets {
				h.pending = append(h.pending, packet)
			}
			h.mu.Unlock()
			continue
		}
		h.mu.Unlock()
		select {
		case active.packets <- packet:
		case <-active.done:
		}
	}
}

const maxPendingPackets = 64

// logHostFrame reports the start of every transaction the USB host begins.
// Only initialization packets are logged (a CTAP message is one init packet
// plus continuations), so a whole makeCredential produces a single line. It is
// the only way to tell "the browser never touched the key" apart from "the key
// answered and the browser rejected the answer".
func logHostFrame(packet []byte) {
	command := packet[4]
	if command&0x80 == 0 {
		return
	}
	log.Printf("host frame cid=%08x cmd=0x%02x len=%d",
		binary.BigEndian.Uint32(packet[:4]), command,
		binary.BigEndian.Uint16(packet[5:7]))
}

// logDeviceFrame is the same line for the other direction, so a transaction
// that never gets an answer is distinguishable from one whose answer the host
// stack dropped. A CBOR reply also carries its status byte, which is what tells
// a refusal apart from a transport failure.
func logDeviceFrame(packet []byte) {
	command := packet[4]
	if command&0x80 == 0 {
		return
	}
	length := binary.BigEndian.Uint16(packet[5:7])
	if command == 0x90 && length > 0 {
		log.Printf("device frame cid=%08x cmd=0x%02x len=%d status=0x%02x",
			binary.BigEndian.Uint32(packet[:4]), command, length, packet[7])
		return
	}
	log.Printf("device frame cid=%08x cmd=0x%02x len=%d",
		binary.BigEndian.Uint32(packet[:4]), command, length)
}

func (h *hidHub) write(s *hidSubscription, packet []byte) error {
	if len(packet) != 64 {
		return errors.New("invalid HID packet")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	select {
	case <-s.done:
		return errHIDSessionSuperseded
	default:
	}
	if h.active != s {
		return errHIDSessionSuperseded
	}
	return h.hid.Write(packet)
}

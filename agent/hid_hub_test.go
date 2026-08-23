package main

import (
	"errors"
	"testing"
	"time"
)

type fakeHID struct {
	reads  chan []byte
	closed chan struct{}
}

func newFakeHID() *fakeHID {
	return &fakeHID{reads: make(chan []byte, 4), closed: make(chan struct{})}
}

func (h *fakeHID) Read() ([]byte, error) {
	select {
	case packet := <-h.reads:
		return packet, nil
	case <-h.closed:
		return nil, errors.New("closed")
	}
}

func (h *fakeHID) Write([]byte) error { return nil }

func (h *fakeHID) Close() error {
	select {
	case <-h.closed:
	default:
		close(h.closed)
	}
	return nil
}

func TestHIDHubRoutesOnlyToCurrentSubscription(t *testing.T) {
	hid := newFakeHID()
	hub := newHIDHub(hid)
	runDone := make(chan struct{})
	go func() {
		_ = hub.run()
		close(runDone)
	}()

	first := hub.subscribe()
	packet := make([]byte, 64)
	hid.reads <- packet
	select {
	case got := <-first.packets:
		if len(got) != 64 {
			t.Fatalf("first packet length=%d", len(got))
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first packet")
	}

	second := hub.subscribe()
	select {
	case <-first.done:
	case <-time.After(time.Second):
		t.Fatal("previous subscription was not closed")
	}

	hid.reads <- packet
	select {
	case <-second.packets:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for replacement subscription")
	}
	select {
	case <-first.packets:
		t.Fatal("packet routed to stale subscription")
	default:
	}

	_ = hid.Close()
	select {
	case <-runDone:
	case <-time.After(time.Second):
		t.Fatal("HID hub did not stop")
	}
}

func TestHIDHubBuffersPacketsBeforeSession(t *testing.T) {
	hid := newFakeHID()
	hub := newHIDHub(hid)
	runDone := make(chan struct{})
	go func() {
		_ = hub.run()
		close(runDone)
	}()

	packet := make([]byte, 64)
	hid.reads <- packet
	deadline := time.Now().Add(time.Second)
	for {
		hub.mu.Lock()
		queued := len(hub.pending)
		hub.mu.Unlock()
		if queued == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("packet was not queued without an active session")
		}
		time.Sleep(time.Millisecond)
	}

	subscription := hub.subscribe()
	select {
	case got := <-subscription.packets:
		if len(got) != 64 {
			t.Fatalf("buffered packet length=%d", len(got))
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for buffered packet")
	}

	_ = hid.Close()
	select {
	case <-runDone:
	case <-time.After(time.Second):
		t.Fatal("HID hub did not stop")
	}
}

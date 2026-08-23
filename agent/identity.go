package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// The phone keeps a list of computers allowed to use the key, so a session
// starts by saying which computer this is. The id is self-assigned and stable
// across runs; the phone stores it and matches on it, which is what makes
// "revoke this laptop" possible without changing the pairing code.

var (
	// errAwaitingApproval means the phone has us on its list but the user has
	// not authorized this computer yet.
	errAwaitingApproval = errors.New("waiting for approval on the phone")
	// errBlocked means the user refused this computer.
	errBlocked = errors.New("this computer is blocked on the phone")
	// errHelloRejected means the phone hung up on the hello frame, which is
	// what an older companion build does.
	errHelloRejected = errors.New("the phone closed the session during hello; update the ABK FIDO app on the phone")
)

const helloAckTimeout = 15 * time.Second

type helloAck struct {
	Type   string `json:"t"`
	Status string `json:"status"`
	Device string `json:"device"`
}

// sayHello introduces this computer and waits for the phone's verdict.
func sayHello(s *session) error {
	id, err := clientID()
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]string{
		"t":    "hello",
		"id":   id,
		"name": clientName(),
		"os":   runtime.GOOS,
	})
	if err != nil {
		return err
	}
	if err := s.write(payload); err != nil {
		return err
	}
	// The phone answers immediately. A deadline keeps a silent peer from
	// parking the session here forever, and an EOF tells us the phone did not
	// understand the frame at all.
	if err := s.conn.SetReadDeadline(time.Now().Add(helloAckTimeout)); err != nil {
		return err
	}
	frame, err := s.read()
	if err != nil {
		_ = s.conn.SetReadDeadline(time.Time{})
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return errHelloRejected
		}
		if isTimeout(err) {
			// Nothing came back, but the session is still open: carry on and
			// let the CTAP traffic decide.
			return nil
		}
		return err
	}
	if err := s.conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	var ack helloAck
	if err := json.Unmarshal(frame, &ack); err != nil || ack.Type != "hello-ack" {
		return fmt.Errorf("unexpected reply to hello (%d bytes)", len(frame))
	}
	switch ack.Status {
	case "authorized":
		if ack.Device != "" {
			log.Printf("authorized by %s", ack.Device)
		}
		return nil
	case "pending":
		return errAwaitingApproval
	case "blocked":
		return errBlocked
	default:
		return fmt.Errorf("phone reported status %q", ack.Status)
	}
}

func isTimeout(err error) bool {
	var timeout interface{ Timeout() bool }
	return errors.As(err, &timeout) && timeout.Timeout()
}

// clientID returns this computer's stable id, creating it on first run. It is
// random rather than derived from hardware: the phone only needs it to be
// stable and unique, and a random value tells it nothing else about the machine.
func clientID() (string, error) {
	path, err := clientIDPath()
	if err == nil {
		if raw, readErr := os.ReadFile(path); readErr == nil {
			if id := normalizeID(string(raw)); id != "" {
				return id, nil
			}
		}
	}
	buf := make([]byte, 16)
	if _, randErr := rand.Read(buf); randErr != nil {
		return "", randErr
	}
	id := hex.EncodeToString(buf)
	if err == nil {
		if mkErr := os.MkdirAll(filepath.Dir(path), 0o700); mkErr == nil {
			if writeErr := os.WriteFile(path, []byte(id+"\n"), 0o600); writeErr != nil {
				log.Printf("could not remember this computer's id in %s: %v", path, writeErr)
			}
		}
	}
	return id, nil
}

func clientIDPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "abk-fido", "client-id"), nil
}

func normalizeID(raw string) string {
	id := strings.ToLower(strings.TrimSpace(raw))
	if len(id) < 16 || len(id) > 64 {
		return ""
	}
	if _, err := hex.DecodeString(id); err != nil {
		return ""
	}
	return id
}

// clientName is what the phone shows in its authorized-computers list.
func clientName() string {
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		sum := sha256.Sum256([]byte(runtime.GOOS))
		return "computer-" + hex.EncodeToString(sum[:3])
	}
	return strings.TrimSpace(host)
}

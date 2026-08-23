package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type session struct {
	aead    cipher.AEAD
	conn    net.Conn
	writeMu sync.Mutex
}

func newSession(conn net.Conn, pairing string) (*session, error) {
	clientNonce := make([]byte, 16)
	if _, err := rand.Read(clientNonce); err != nil {
		return nil, err
	}
	if _, err := conn.Write(clientNonce); err != nil {
		return nil, err
	}
	serverNonce := make([]byte, 16)
	if _, err := io.ReadFull(conn, serverNonce); err != nil {
		return nil, err
	}
	b, err := aes.NewCipher(deriveKey(pairing, append(clientNonce, serverNonce...)))
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return &session{aead: a, conn: conn}, nil
}

func deriveKey(password string, salt []byte) []byte {
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write(append(salt, 0, 0, 0, 1))
	t := mac.Sum(nil)
	out := append([]byte(nil), t...)
	for i := 1; i < 100000; i++ {
		mac = hmac.New(sha256.New, []byte(password))
		mac.Write(t)
		t = mac.Sum(nil)
		for j := range out {
			out[j] ^= t[j]
		}
	}
	return out
}

func (s *session) read() ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(s.conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > 4096 {
		return nil, errors.New("frame too large")
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(s.conn, nonce); err != nil {
		return nil, err
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(s.conn, body); err != nil {
		return nil, err
	}
	return s.aead.Open(nil, nonce, body, nil)
}

func (s *session) write(p []byte) error {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := s.aead.Seal(nil, nonce, p, nil)
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(sealed)))
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.conn.Write(h[:]); err != nil {
		return err
	}
	if _, err := s.conn.Write(nonce); err != nil {
		return err
	}
	_, err := s.conn.Write(sealed)
	return err
}

func relay(conn net.Conn, pairing string, hub *hidHub) error {
	s, err := newSession(conn, pairing)
	if err != nil {
		return err
	}
	defer conn.Close()
	subscription := hub.subscribe()
	defer hub.unsubscribe(subscription)
	writeErrors := make(chan error, 1)
	go func() {
		for {
			select {
			case <-subscription.done:
				// A newer authenticated session owns the UHID stream now. Close
				// this socket so the old relay cannot remain blocked in s.read().
				_ = conn.Close()
				return
			case p := <-subscription.packets:
				if e := s.write(p); e != nil {
					select {
					case writeErrors <- e:
					default:
					}
					_ = conn.Close()
					return
				}
			}
		}
	}()
	for {
		select {
		case err := <-writeErrors:
			return err
		default:
		}
		p, e := s.read()
		if e != nil {
			return e
		}
		if len(p) != 64 {
			return errors.New("invalid CTAP packet")
		}
		if e = hub.write(subscription, p); e != nil {
			return e
		}
	}
}

func main() {
	pairing := flag.String("pairing", "", "pairing code / PSK (required)")
	phone := flag.String("phone", "", "phone LAN address, e.g. 192.168.1.20:38741 (auto-discovered when omitted)")
	flag.Parse()
	// Check the virtual-key backend before anything interactive: it needs root
	// on Linux, and on Windows it needs the abkfidovhid driver installed and an
	// elevated prompt. Either way the user should learn that before the phone
	// shows a pairing code.
	if err := checkHIDBackend(); err != nil {
		log.Fatal(err)
	}
	if *phone == "" {
		var err error
		*phone, err = discoverPhone()
		if err != nil {
			log.Fatal(err)
		}
	}
	if *pairing == "" {
		requestPairing(*phone)
		fmt.Print("Enter the pairing code shown on the phone: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		*pairing = strings.TrimSpace(line)
		if *pairing == "" {
			log.Fatal("pairing code is required")
		}
	}
	hid, err := NewHID("")
	if err != nil {
		log.Fatal(err)
	}
	defer hid.Close()
	hub := newHIDHub(hid)
	go func() {
		if err := hub.run(); err != nil {
			log.Printf("UHID reader stopped: %v", err)
		}
	}()
	// The relay is idle whenever the USB host is not talking to the key, so keep
	// SO_KEEPALIVE on to detect a phone that disappears without closing.
	dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	for {
		conn, err := dialer.Dial("tcp", *phone)
		if err != nil {
			log.Printf("phone connect: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		log.Printf("relay connected to %s", *phone)
		if err := relay(conn, *pairing, hub); err != nil {
			if errors.Is(err, io.EOF) {
				log.Print("phone closed the relay session; reconnecting")
			} else {
				log.Printf("session ended: %v", err)
			}
		}
		time.Sleep(time.Second)
	}
}

const (
	discoveryPort = 38740
	// discoveryProbes repeats the broadcast because the first probe is
	// regularly lost on Windows: the firewall only decides whether to admit the
	// phone's unicast answer once the program has asked for the first time, and
	// the answer to that first probe is dropped while the prompt is open.
	discoveryProbes = 3
)

func discoverPhone() (string, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	targets := broadcastTargets()
	msg := []byte("ABK_FIDO_DISCOVER_V1")
	seen := map[string]bool{}
	var devices []string
	buf := make([]byte, 128)
	for probe := 0; probe < discoveryProbes && len(devices) == 0; probe++ {
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		var sendErr error
		sent := 0
		for _, target := range targets {
			if _, e := conn.WriteToUDP(msg, target); e != nil {
				sendErr = e
				continue
			}
			sent++
		}
		if sent == 0 {
			return "", sendErr
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		for {
			n, addr, e := conn.ReadFromUDP(buf)
			if e != nil {
				break
			}
			if string(buf[:n]) != "ABK_FIDO_HERE_V1" {
				continue
			}
			phone := fmt.Sprintf("%s:38741", addr.IP.String())
			if !seen[phone] {
				seen[phone] = true
				devices = append(devices, phone)
			}
		}
	}
	if len(devices) == 0 {
		return "", fmt.Errorf("no ABK FIDO devices answered on UDP %d after probing %d broadcast address(es): "+
			"check that the companion app is running on the same network and that the desktop firewall lets the "+
			"reply in, or name the phone with -phone <ip>:38741", discoveryPort, len(targets))
	}
	for i, d := range devices {
		fmt.Printf("[%d] %s\n", i+1, d)
	}
	if len(devices) == 1 {
		return devices[0], nil
	}
	fmt.Print("Select device: ")
	var choice int
	if _, err := fmt.Scan(&choice); err != nil || choice < 1 || choice > len(devices) {
		return "", fmt.Errorf("invalid device selection")
	}
	return devices[choice-1], nil
}

// broadcastTargets lists the addresses a discovery probe is sent to. A probe to
// 255.255.255.255 leaves through the single interface the routing table picks,
// which on Windows is regularly a Hyper-V or WSL virtual switch rather than the
// adapter the phone is on, so each up interface's own directed broadcast is
// probed as well.
func broadcastTargets() []*net.UDPAddr {
	targets := []*net.UDPAddr{{IP: net.IPv4bcast, Port: discoveryPort}}
	interfaces, err := net.Interfaces()
	if err != nil {
		return targets
	}
	seen := map[string]bool{net.IPv4bcast.String(): true}
	for _, iface := range interfaces {
		const wanted = net.FlagUp | net.FlagBroadcast
		if iface.Flags&wanted != wanted || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, e := iface.Addrs()
		if e != nil {
			continue
		}
		for _, addr := range addrs {
			network, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			broadcast := directedBroadcast(network)
			if broadcast == nil || seen[broadcast.String()] {
				continue
			}
			seen[broadcast.String()] = true
			targets = append(targets, &net.UDPAddr{IP: broadcast, Port: discoveryPort})
		}
	}
	return targets
}

// directedBroadcast returns the IPv4 broadcast address of an interface network.
// It returns nil for anything that cannot carry a broadcast: IPv6 addresses, and
// point-to-point /32s whose broadcast address is the interface address itself.
func directedBroadcast(network *net.IPNet) net.IP {
	ip := network.IP.To4()
	mask := network.Mask
	if len(mask) == net.IPv6len {
		mask = mask[12:]
	}
	if ip == nil || len(mask) != net.IPv4len {
		return nil
	}
	broadcast := make(net.IP, net.IPv4len)
	for i := range broadcast {
		broadcast[i] = ip[i] | ^mask[i]
	}
	if broadcast.Equal(ip) {
		return nil
	}
	return broadcast
}

func requestPairing(phone string) {
	host, _, splitErr := net.SplitHostPort(phone)
	if splitErr != nil {
		host = phone
	}
	addr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(host, strconv.Itoa(discoveryPort)))
	if err != nil {
		log.Printf("pairing request: %v", err)
		return
	}
	c, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		log.Printf("pairing request: %v", err)
		return
	}
	defer c.Close()
	_, _ = c.Write([]byte("ABK_FIDO_PAIR_REQUEST_V1"))
}

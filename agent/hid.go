package main

// reportLen is the fixed CTAP HID report size.
const reportLen = 64

type HID interface {
	Read() ([]byte, error)
	Write([]byte) error
	Close() error
}

// hidStats is implemented by a backend that can say what the local HID stack
// did with the frames handed to it. Only the Windows virtual HID driver keeps
// such counters; on Linux the kernel's uhid path has no equivalent.
type hidStats interface {
	Stats() (string, error)
}

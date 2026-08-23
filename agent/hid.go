package main

// reportLen is the fixed CTAP HID report size.
const reportLen = 64

type HID interface {
	Read() ([]byte, error)
	Write([]byte) error
	Close() error
}

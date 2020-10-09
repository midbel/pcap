package pcap

import (
	"encoding/binary"
	"errors"
	"io"
	"time"
)

const (
	nano  = 0xa1b2c3d4
	micro = 0xd4c3b2a1
)

var ErrMagic = errors.New("bad magic number")

type Header struct {
	Seconds uint32
	Nanos   uint32
	Len     uint32
	Size    uint32
}

func (h Header) Time() time.Time {
	t := time.Unix(int64(h.Seconds), int64(h.Nanos))
	return t.UTC()
}

func Decode(r io.Reader, fn func([]byte, Header) error) error {
	top := struct {
		Magic uint32
		Major uint16
		Minor uint16
		Corr  uint32
		Acc   uint32
		Len   uint32
		Net   uint32
	}{}
	if err := binary.Read(r, binary.LittleEndian, &top); err != nil {
		return err
	}
	switch top.Magic {
	case micro, nano:
	default:
		return ErrMagic
	}
	var (
		hdr Header
		buf []byte
	)
	for {
		if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if top.Magic == micro {
			hdr.Nanos *= 1000
		}
		buf = make([]byte, hdr.Len)
		if _, err := io.ReadFull(r, buf); err != nil {
			return err
		}
		if err := fn(buf, hdr); err != nil {
			return err
		}
	}
	return nil
}

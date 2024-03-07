package main

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
)

// The methods below convert struct http_trace's fields to useable values.

type ContentLength uint32

const (
	UnknownLength ContentLength = math.MaxUint32 - iota
	MaxLength
)

func (l ContentLength) String() string {
	switch l {
	case UnknownLength:
		return "<unk>"
	case MaxLength:
		return fmt.Sprintf("%d+", MaxLength)
	default:
		return strconv.FormatUint(uint64(l), 10)
	}
}

func (t *probeHttpTrace) Protocol() string {
	major := t.Head.Protocol >> 4
	minor := t.Head.Protocol & 0xf
	return fmt.Sprintf("HTTP/%d.%d", major, minor)
}

func (t *probeHttpTrace) Method() []byte {
	return t.Buf[:t.Head.MethodEnd]
}

func (t *probeHttpTrace) URL() []byte {
	return t.Buf[t.Head.MethodEnd:t.Head.UrlEnd]
}

func (t *probeHttpTrace) Status() string {
	if text := http.StatusText(int(t.Head.StatusCode)); text != "" {
		return fmt.Sprintf("%d %s", t.Head.StatusCode, text)
	}
	return strconv.FormatUint(uint64(t.Head.StatusCode), 10)
}

func (t *probeHttpTrace) String() string {
	app := AppID(int(t.Head.Pid))
	if app == "" {
		app = fmt.Sprintf("P-%d", t.Head.Pid)
	}

	length := ContentLength(t.Head.ContentLength)
	return fmt.Sprintf(
		"%s -[%s %s]-> %s [%s, %s bytes]",
		app, t.Method(), t.Protocol(), t.URL(), t.Status(), length,
	)
}

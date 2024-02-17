package main

import (
	"fmt"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/prometheus/procfs"
)

var (
	proc         procfs.FS
	appIDEnvVars = []string{"NAME", "IDENTITY", "APP_NAME", "APP_ID"}
)

func init() {
	var err error
	proc, err = procfs.NewDefaultFS()
	if err != nil {
		panic(err)
	}
}

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
	app := appID(t.Head.Pid)
	if app == "" {
		app = fmt.Sprintf("P-%d", t.Head.Pid)
	}

	length := ContentLength(t.Head.ContentLength)
	return fmt.Sprintf(
		"%s -[%s %s]-> %s [%s, %s bytes]",
		app, t.Method(), t.Protocol(), t.URL(), t.Status(), length,
	)
}

func appID(pid uint32) string {
	c, err := proc.Proc(int(pid))
	if err != nil {
		return ""
	}

	app, _ := c.Comm()
	env, _ := c.Environ()
	ids := filterAppIDEnv(env)
	if len(ids) == 0 {
		return app
	}

	return fmt.Sprintf("%s@%s", app, strings.Join(ids, "-"))
}

func filterAppIDEnv(env []string) (ids []string) {
	for _, val := range env {
		k, v, ok := strings.Cut(val, "=")
		if ok && slices.Contains(appIDEnvVars, k) {
			ids = append(ids, v)
		}
	}
	return
}

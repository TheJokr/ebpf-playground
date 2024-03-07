package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

func readRingbuf(rbMap *ebpf.Map) {
	rb, err := ringbuf.NewReader(rbMap)
	if err != nil {
		log.Fatalf("setup ringbuf reader: %v", err)
	}

	go func() {
		// The ringbuf package doesn't support context.Context,
		// so we have to roll our own graceful shutdown handling.
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
		<-ch
		_ = rb.Close()
	}()

	var rec ringbuf.Record
	var reader bytes.Reader
	var trace probeHttpTrace
	g := newHttpGraph()

	for {
		if err := rb.ReadInto(&rec); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			log.Printf("read from ringbuf: %v", err)
			continue
		}

		reader.Reset(rec.RawSample)
		if err := binary.Read(&reader, binary.NativeEndian, &trace); err != nil {
			log.Printf("decode ringbuf record: %v", err)
			continue
		}
		if reader.Len() > 0 {
			log.Printf("decode ringbuf record: %d bytes left over", reader.Len())
			continue
		}

		log.Print(&trace)
		g.add(&trace)
	}

	log.Printf("HTTP dependency graph (DOT): %s", g.dot())
}

type httpGraph struct {
	// src pid -> dst host -> count
	adj map[uint32]map[string]uint
}

func newHttpGraph() httpGraph {
	return httpGraph{adj: make(map[uint32]map[string]uint)}
}

func (g httpGraph) add(trace *probeHttpTrace) {
	url, err := url.Parse(string(trace.URL()))
	if err != nil {
		log.Printf("parse trace URL: %v", err)
		return
	}

	dests := g.adj[trace.Head.Pid]
	if dests == nil {
		dests = make(map[string]uint)
		g.adj[trace.Head.Pid] = dests
	}

	dests[url.Host] += 1
}

func (g httpGraph) dot() string {
	socks := LoadTCPSocketProcs()
	var o strings.Builder
	o.WriteString("strict digraph {\n")

	for src, edges := range g.adj {
		srcID := dotQuote(AppID(int(src)))
		for dstHost, cnt := range edges {
			dstID := dstHost
			if dst, err := socks.HostPid(dstHost); err == nil {
				dstID = AppID(dst)
			}

			fmt.Fprintf(&o, "%s -> %s [xlabel=%d]\n", srcID, dotQuote(dstID), cnt)
		}
	}

	o.WriteRune('}')
	return o.String()
}

func dotQuote(v string) string {
	quoted, _ := json.Marshal(v)
	return string(quoted)
}

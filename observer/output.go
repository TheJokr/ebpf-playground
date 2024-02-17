package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
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

	for {
		if err := rb.ReadInto(&rec); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
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
	}
}

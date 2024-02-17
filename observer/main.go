package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type http_trace probe bpf/probe.c -- -mcpu=v3 -Wall -Wextra -D__x86_64__ -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 -type http_trace probe bpf/probe.c -- -mcpu=v3 -Wall -Wextra -I/usr/include/aarch64-linux-gnu

func main() {
	log.SetFlags(log.Ltime)
	log.SetPrefix("observer ")

	probe := mustLoadProbe()
	defer probe.Close()
	ex, elf := mustLoadExecutable()

	funcOffs, err := elf.FindFunction("net/http.(*Transport).RoundTrip")
	_ = elf.Close()
	if err != nil {
		log.Fatalf("find net/http.(*Transport).RoundTrip(...) offsets: %v", err)
	}

	// uretprobe crashes Go's runtime when it has to grow the stack,
	// so we have to manually instrument every return instruction. This
	// feature is not built into cilium/ebpf natively, which is why we
	// re-implement the function address/offset loading from ELF.
	links := make([]io.Closer, 0, len(funcOffs.Returns))
	for _, off := range funcOffs.Returns {
		opts := link.UprobeOptions{Address: funcOffs.Address, Offset: off}
		l, err := ex.Uprobe("", probe.HttpTransportRoundtripRet, &opts)
		if err != nil {
			log.Fatalf("attach to executable: %v", err)
		}
		links = append(links, l)
	}
	defer _ProbeClose(links...)

	log.Printf("%d http probe(s) attached!", len(links))
	readRingbuf(probe.Traces)
	log.Println("bye!")
}

// mustLoadProbe used to be just an error-handling wrapper around
// bpf2go's loadProbeObjects. However, because of the addition of the
// pidns_* constants, we now also have to modify the spec in-between.
func mustLoadProbe() (probe probeObjects) {
	spec, err := loadProbe()
	if err != nil {
		log.Fatal(err)
	}
	if err := injectPidnsDescriptor(spec); err != nil {
		log.Fatalf("load constants for eBPF probe: %v", err)
	}

	if err := spec.LoadAndAssign(&probe, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			err = ve
		}
		log.Fatalf("load eBPF probe into kernel: %+v", err)
	}
	return
}

func injectPidnsDescriptor(spec *ebpf.CollectionSpec) error {
	var stat unix.Stat_t
	if err := unix.Stat("/proc/self/ns/pid", &stat); err != nil {
		return fmt.Errorf("stat our pid ns: %w", err)
	}

	return spec.RewriteConstants(map[string]interface{}{
		"pidns_dev": stat.Dev,
		"pidns_ino": stat.Ino,
	})
}

func mustLoadExecutable() (*link.Executable, *ELFFile) {
	if len(os.Args) < 2 {
		log.Fatalf("missing program to attach to: %s /path/to/exec", os.Args[0])
	}
	ex, err := link.OpenExecutable(os.Args[1])
	if err != nil {
		log.Fatalf("open executable: %v", err)
	}

	elf, err := OpenELFFile(os.Args[1])
	if err != nil {
		log.Fatalf("open executable: %v", err)
	}
	return ex, elf
}

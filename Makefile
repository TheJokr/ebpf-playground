.SUFFIXES:
.PHONY: default all observer test-svc disasm run-mesh observe-mesh graph
default: observer
all: observer test-svc

observer: /tmp/observer
	@echo 'Built $@ at $<' >&2
test-svc: /tmp/test-svc
	@echo 'Built $@ at $<' >&2

# Build observer
probes := bpfel_x86 bpfel_arm64
probes := $(patsubst %,observer/probe_%.go,$(probes))
$(probes) &: observer/bpf/*
	go generate -x ./observer

/tmp/observer: observer/*.go $(probes)
	go build -o '$@' ./observer
	sudo setcap 'cap_sys_admin=ep' '$@'

# Build test-svc
/tmp/test-svc: mesh/*.go
	go build -o '$@' ./mesh

# Utility commands
disasm: $(probes)
	@llvm-objdump -dS -fhr --no-show-raw-insn '$(<:.go=.o)'

run-mesh:
	@exec mesh/fake-mesh.sh

observe-mesh: /tmp/observer
	@exec '$<' /tmp/fake-service

graph: g ?= g.dot
graph:
	dot -Tpng -O -Gdpi=300 -Nshape=egg -Npenwidth=2 -Epenwidth=2.5 '$(g)'

package main

import "golang.org/x/arch/arm64/arm64asm"

func findReturns(data []byte) ([]uint64, error) {
	var offs []uint64
	for idx := 0; idx < len(data); idx += 4 {
		insn, err := arm64asm.Decode(data[idx:])
		if err == nil && insn.Op == arm64asm.RET {
			offs = append(offs, uint64(idx))
		}
	}

	return offs, nil
}

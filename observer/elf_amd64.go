package main

import "golang.org/x/arch/x86/x86asm"

func findReturns(data []byte) ([]uint64, error) {
	var offs []uint64
	for idx := 0; idx < len(data); {
		insn, err := x86asm.Decode(data[idx:], 64)
		if err != nil {
			// can't proceed, x86 has variable instruction length
			return nil, err
		}

		if insn.Op == x86asm.RET {
			offs = append(offs, uint64(idx))
		}
		idx += insn.Len
	}

	return offs, nil
}

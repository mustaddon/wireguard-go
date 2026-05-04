package device

import (
	"encoding/binary"
	"math/rand/v2"
	"time"
)

func AddHiddenHeader(packet []byte, msgType uint32) []byte {
	rnd := byte(rand.UintN(256))
	if rnd < 16 {
		rnd |= 0x10
	}
	hlen := HiddenHeaderLen(rnd)
	hidden := make([]byte, len(packet)+hlen)
	if hlen > 1 {
		binary.LittleEndian.PutUint32(hidden, uint32(time.Now().UnixNano()>>hlen))
	}
	hidden[0] = rnd
	copy(hidden[hlen:], packet[0:])
	return hidden
}

func HiddenHeaderLen(val byte) int {
	return 1 + (int(val) & 3)
}

func MsgHiddenType(val uint32) uint32 {
	return val & 7
}

func HiddenType(val uint32) uint32 {
	result := uint32(time.Now().UnixNano())
	return (result &^ 0xFF) | uint32(int(result&0xFF)+int(val)-int(MsgHiddenType(result)))
}

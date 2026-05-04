package device

import (
	"time"
	"unsafe"
)

func AddHiddenHeader(packet []byte, msgType uint32) []byte {
	hidden := make([]byte, len(packet)+2)
	copy(hidden[2:], packet[0:])
	hidden[0] = 1
	hidden[1] = byte(msgType)
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
	byteSlice := (*[4]byte)(unsafe.Pointer(&result))[:]
	byteSlice[0] = byte(int(byteSlice[0]) + (int(val) - int(MsgHiddenType(result))))
	return result
}

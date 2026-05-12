package device

import (
	"encoding/binary"
	"math/rand/v2"
	"time"
	"unsafe"
)

var MASK = [32]byte{
	0x81, 0xab, 0xa4, 0x0d, 0xb7, 0x73, 0x42, 0x2b,
	0xd0, 0x79, 0x2d, 0x65, 0xce, 0x69, 0x1f, 0x82,
	0x98, 0x31, 0x89, 0xaf, 0xd6, 0x5c, 0x85, 0x93,
	0x8b, 0x90, 0x52, 0x33, 0x17, 0xff, 0x18, 0x57}

func GetMask(device *Device) []uint32 {
	return unsafe.Slice((*uint32)(unsafe.Pointer(&MASK[0])), 8)
}

func IntSlice(buffer []byte, len int) []uint32 {
	return unsafe.Slice((*uint32)(unsafe.Pointer(&buffer[0])), len)
}

func XorHead(buffer []byte, mask []uint32) {
	ptr := IntSlice(buffer, 1)
	ptr[0] ^= mask[0]
}

func XorData(buffer []byte, mask []uint32) {
	ptr := IntSlice(buffer, 4)
	ptr[1] ^= ptr[0] ^ mask[1]
	ptr[2] ^= ptr[0] ^ mask[2]
	ptr[3] ^= ptr[0] ^ mask[3]
}

func XorInit(buffer []byte, mask []uint32) {
	ptr := IntSlice(buffer, 2)
	ptr[1] ^= ptr[0] ^ mask[1]
	XorMac2(buffer, mask, ptr[0])
}

func XorResp(buffer []byte, mask []uint32) {
	ptr := IntSlice(buffer, 3)
	ptr[1] ^= ptr[0] ^ mask[1]
	ptr[2] ^= ptr[0] ^ mask[2]
	XorMac2(buffer, mask, ptr[0])
}

func XorMac2(buffer []byte, mask []uint32, head uint32) {
	ptr := IntSlice(buffer[len(buffer)-16:], 4)
	ptr[0] ^= head ^ mask[4]
	ptr[1] ^= head ^ mask[5]
	ptr[2] ^= head ^ mask[6]
	ptr[3] ^= head ^ mask[7]
}

func XorCook(buffer []byte, mask []uint32) {
	ptr := IntSlice(buffer, 2)
	ptr[1] ^= ptr[0] ^ mask[1]
}

func MsgHiddenType(val byte) byte {
	return val & 7
}

func HiddenLen(val byte) int {
	return int((val & 7) + 4)
}

func RemoveHidden(buffer []byte, device *Device) int {
	if len(buffer) < MinMessageSize {
		return -1
	}

	mask := GetMask(device)
	XorHead(buffer, mask)

	msgType := MsgHiddenType(buffer[3])
	hlen := 0

	if msgType == 0 {
		hlen = HiddenLen(buffer[3] >> 3)
		msgType = MsgHiddenType(buffer[3+hlen])
	}

	switch msgType {
	case MessageTransportType:
		XorData(buffer[hlen:], mask)
	case MessageInitiationType:
		XorInit(buffer[hlen:], mask)
	case MessageResponseType:
		XorResp(buffer[hlen:], mask)
	case MessageCookieReplyType:
		XorCook(buffer[hlen:], mask)
	default:
		return -1
	}

	return hlen
}

func AddHiddenHeader(packet []byte, msgType uint32) []byte {
	hlen := HiddenLen(byte(rand.UintN(256)))
	hidden := make([]byte, len(packet)+hlen)
	ptr := IntSlice(hidden, 3)
	ptr[0] = rand.Uint32()
	ptr[1] = rand.Uint32()
	ptr[2] = rand.Uint32()
	hidden[3] = (hidden[3] << 6) | (byte(hlen-4) << 3)
	copy(hidden[hlen:], packet)
	return hidden
}

func ApplyHidden(packet []byte, msgType uint32, device *Device) []byte {
	hidden := packet
	mask := GetMask(device)

	binary.BigEndian.PutUint32(hidden, (uint32(time.Now().UnixNano())<<3)|msgType)

	switch msgType {
	case MessageTransportType:
		XorData(packet, mask)
		if len(packet) == MessageKeepaliveSize {
			hidden = AddHiddenHeader(packet, msgType)
		}
	case MessageInitiationType:
		XorInit(packet, mask)
		hidden = AddHiddenHeader(packet, msgType)
	case MessageResponseType:
		XorResp(packet, mask)
		hidden = AddHiddenHeader(packet, msgType)
	case MessageCookieReplyType:
		XorCook(packet, mask)
		hidden = AddHiddenHeader(packet, msgType)
	}

	XorHead(hidden, mask)
	return hidden
}

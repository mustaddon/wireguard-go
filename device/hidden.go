package device

import (
	"encoding/binary"
	"math/rand/v2"
	"unsafe"
)

var MASK = [32]byte{
	0x81, 0xab, 0xa4, 0x0d, 0xb7, 0x73, 0x42, 0x2b,
	0xd0, 0x79, 0x2d, 0x65, 0xce, 0x69, 0x1f, 0x82,
	0x98, 0x31, 0x89, 0xaf, 0xd6, 0x5c, 0x85, 0x93,
	0x8b, 0x90, 0x52, 0x33, 0x17, 0xff, 0x18, 0x57}

func ByteMask(device *Device) [32]byte {
	return MASK
}

func GetMask(device *Device) []uint32 {
	return unsafe.Slice((*uint32)(unsafe.Pointer(&MASK[0])), 8)
}

func IntSlice(buffer []byte, len int) []uint32 {
	return unsafe.Slice((*uint32)(unsafe.Pointer(&buffer[0])), len)
}

func XorHead(buffer []byte, mask []uint32) {
	IntSlice(buffer, 1)[0] ^= mask[0]
}

func XorData(buffer []byte, mask []uint32) {
	ptr := IntSlice(buffer, 4)
	ptr[1] ^= ptr[0] ^ mask[1]
	ptr[2] ^= ptr[0] ^ mask[2]
	ptr[3] ^= ptr[0] ^ mask[3]
}

func XorCook(buffer []byte, mask []uint32) {
	ptr := IntSlice(buffer, 2)
	ptr[1] ^= ptr[0] ^ mask[1]
}

func XorInit(buffer []byte, mask []uint32) {
	ptr := IntSlice(buffer, 2)
	ptr[1] ^= ptr[0] ^ mask[1]
	XorMac2(buffer, ptr[0], mask)
}

func XorResp(buffer []byte, mask []uint32) {
	ptr := IntSlice(buffer, 3)
	ptr[1] ^= ptr[0] ^ mask[1]
	ptr[2] ^= ptr[0] ^ mask[2]
	XorMac2(buffer, ptr[0], mask)
}

func XorMac2(buffer []byte, zero uint32, mask []uint32) {
	ptr := IntSlice(buffer[len(buffer)-16:], 4)
	ptr[0] ^= zero ^ mask[4]
	ptr[1] ^= zero ^ mask[5]
	ptr[2] ^= zero ^ mask[6]
	ptr[3] ^= zero ^ mask[7]
}

func MsgHiddenType(val byte) uint32 {
	return uint32(val & 7)
}

func HiddenLen(val byte) int {
	return int((val & 3) + 1)
}

func RemoveHidden(buffer []byte, device *Device) int {
	if len(buffer) < MinMessageSize {
		return -1
	}

	tmp := buffer[0] ^ ByteMask(device)[0]
	msgType := MsgHiddenType(tmp)
	mask := GetMask(device)
	hlen := 0

	if msgType == 0 {
		hlen = HiddenLen(tmp >> 3)
		buffer = buffer[hlen:]
		XorHead(buffer, mask)
		msgType = MsgHiddenType(buffer[0])
	} else {
		XorHead(buffer, mask)
	}

	switch msgType {
	case MessageTransportType:
		XorData(buffer, mask)
	case MessageInitiationType:
		XorInit(buffer, mask)
	case MessageResponseType:
		XorResp(buffer, mask)
	case MessageCookieReplyType:
		XorCook(buffer, mask)
	default:
		return -1
	}

	binary.LittleEndian.PutUint32(buffer, msgType)

	return hlen
}

func AddHiddenHeader(packet []byte, msgType uint32, mask []uint32) []byte {
	hlen := HiddenLen(byte(rand.Uint32()))
	hidden := make([]byte, len(packet)+hlen)
	binary.LittleEndian.PutUint32(hidden, (rand.Uint32()<<5)|(uint32(hlen-1)<<3))
	XorHead(hidden, mask)
	copy(hidden[hlen:], packet)
	return hidden
}

func ApplyHidden(packet []byte, msgType uint32, device *Device) []byte {
	mask := GetMask(device)

	binary.LittleEndian.PutUint32(packet, (rand.Uint32()<<3)|msgType)

	if msgType == MessageTransportType {
		XorData(packet, mask)
		if len(packet) != MessageKeepaliveSize {
			XorHead(packet, mask)
			return packet
		}
	} else {
		switch msgType {
		case MessageInitiationType:
			XorInit(packet, mask)
		case MessageResponseType:
			XorResp(packet, mask)
		case MessageCookieReplyType:
			XorCook(packet, mask)
		}
	}

	XorHead(packet, mask)
	return AddHiddenHeader(packet, msgType, mask)
}

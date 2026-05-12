package device

import (
	"encoding/binary"
	"time"
)

var mask = [32]byte{
	0x81, 0xab, 0xa4, 0x0d, 0xb7, 0x73, 0x42, 0x2b,
	0xd0, 0x79, 0x2d, 0x65, 0xce, 0x69, 0x1f, 0x82,
	0x98, 0x31, 0x89, 0xaf, 0xd6, 0x5c, 0x85, 0x93,
	0x8b, 0x90, 0x52, 0x33, 0x17, 0xff, 0x18, 0x57}

func RemoveHidden(buffer *[MaxMessageSize]byte, device *Device) int {
	msgType := buffer[3] & 7
	hlen := 0

	if msgType == 0 {
		hlen = 4 + (int(buffer[3]>>3) & 7)
		msgType = buffer[3+hlen] & 7
	}

	switch msgType {
	case MessageTransportType:

	case MessageInitiationType:

	case MessageResponseType:

	case MessageCookieReplyType:

	}

	return hlen
}

func ApplyHidden(packet []byte, msgType uint32, device *Device) []byte {
	hidden := packet

	binary.BigEndian.PutUint32(hidden, (uint32(time.Now().UnixNano())<<3)|msgType)

	switch msgType {
	case MessageTransportType:

		if len(packet) == MessageKeepaliveSize {

		}
	case MessageInitiationType:

	case MessageResponseType:

	case MessageCookieReplyType:

	}

	// rnd := byte(rand.UintN(256))
	// if rnd < 16 {
	// 	rnd |= 0x10
	// }
	// hlen := HiddenHeaderLen(rnd)
	// hidden := make([]byte, len(packet)+hlen)
	// if hlen > 1 {
	// 	binary.LittleEndian.PutUint32(hidden, uint32(time.Now().UnixNano()>>hlen))
	// }
	// hidden[0] = rnd
	// copy(hidden[hlen:], packet)
	return hidden
}

func HiddenHeaderLen(val byte) int {
	return 1 + (int(val) & 3)
}

func MsgHiddenType(val uint32) uint32 {
	return val & 7
}

func HiddenType(val uint32) uint32 {
	noise := uint32(time.Now().UnixNano())
	return (noise &^ 0xFF) | uint32(int(noise&0xFF)+int(val)-int(MsgHiddenType(noise)))
}

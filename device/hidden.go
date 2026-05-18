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

func XorHead(buffer []byte, device *Device) {
	buffer[0] = (buffer[0] & 0xF0) | ((buffer[0] ^ ByteMask(device)[0]) & 0x0F)
}

func XorData(buffer []byte, mask []uint32) {
	ptr := IntSlice(buffer, 4)
	zero := ptr[0] ^ mask[0]
	ptr[1] ^= zero ^ mask[1]
	ptr[2] ^= zero ^ mask[2]
	ptr[3] ^= zero ^ mask[3]
}

func XorCook(buffer []byte, mask []uint32) {
	ptr := IntSlice(buffer, 2)
	zero := ptr[0] ^ mask[0]
	ptr[1] ^= zero ^ mask[1]
}

func XorInit(buffer []byte, mask []uint32) {
	ptr := IntSlice(buffer, 2)
	zero := ptr[0] ^ mask[0]
	ptr[1] ^= zero ^ mask[1]
	XorMac2(buffer, zero, mask)
}

func XorResp(buffer []byte, mask []uint32) {
	ptr := IntSlice(buffer, 3)
	zero := ptr[0] ^ mask[0]
	ptr[1] ^= zero ^ mask[1]
	ptr[2] ^= zero ^ mask[2]
	XorMac2(buffer, zero, mask)
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
	return int(val & 7)
}

const (
	QUIC_INIT_LEN = 21
	QUIC_RESP_LEN = 16
	QUIC_COOK_LEN = 13
	QUIC_DATA_LEN = 4
)

func RemoveHidden(buffer []byte, device *Device) int {
	if len(buffer) < MinMessageSize {
		return -1
	}

	XorHead(buffer, device)
	msgType := uint32(0)
	hlen := HiddenLen(buffer[0])

	if (buffer[0] & 0x80) != 0 {
		if buffer[5] != 3 {
			hlen += QUIC_INIT_LEN
			msgType = MessageInitiationType
		} else if buffer[9] != 0 {
			hlen += QUIC_RESP_LEN
			msgType = MessageResponseType
		} else {
			hlen += QUIC_COOK_LEN
			msgType = MessageCookieReplyType
		}
		buffer = buffer[hlen:]
	} else {
		msgType = MessageTransportType
		if hlen > 0 {
			hlen += QUIC_DATA_LEN
			buffer = buffer[hlen:]
		}
	}

	mask := GetMask(device)

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

func AddHiddenHeader(packet []byte, qlen int, hlen int) ([]byte, int) {
	tlen := qlen + hlen
	hidden := make([]byte, len(packet)+tlen)
	if hlen > 0 {
		if tlen > 8 {
			binary.LittleEndian.PutUint64(hidden[tlen-8:], rand.Uint64())
		} else if tlen > 4 {
			binary.LittleEndian.PutUint32(hidden[tlen-4:], rand.Uint32())
		}
	}
	copy(hidden[tlen:], packet)
	return hidden, tlen
}

func AddQuicInitHeader(packet []byte, qlen int) ([]byte, int) {
	flags := 0xC0 | byte(rand.Uint32()&0x0F)
	hlen := HiddenLen(flags)
	quic, offset := AddHiddenHeader(packet, qlen, hlen)
	quic[0] = flags
	binary.BigEndian.PutUint32(quic[1:], 1)
	quic[qlen-3] = 0
	binary.BigEndian.PutUint16(quic[qlen-2:], 0x4000|uint16(hlen+len(packet)))
	return quic, offset
}

func AddQuicDataHeader(packet []byte) ([]byte, int) {
	flags := 0x40 | byte(rand.Uint32()&0x1F)
	quic, offset := AddHiddenHeader(packet, QUIC_DATA_LEN, HiddenLen(flags))
	quic[0] = flags
	copy(quic[1:4], packet[4:])
	return quic, offset
}

func ApplyHidden(packet []byte, msgType uint32, device *Device) []byte {
	mask := GetMask(device)

	if msgType == MessageTransportType && len(packet) != MessageKeepaliveSize {
		packet[0] = (byte(rand.Uint32()) & 0x18) | 0x40
		copy(packet[1:4], packet[4:])
		XorData(packet, mask)
		XorHead(packet, device)
		return packet
	}

	binary.LittleEndian.PutUint32(packet, rand.Uint32())
	quic := packet
	qlen := 0

	switch msgType {
	case MessageTransportType:
		quic, qlen = AddQuicDataHeader(packet)
		XorData(quic[qlen:], mask)
	case MessageInitiationType:
		quic, qlen = AddQuicInitHeader(packet, QUIC_INIT_LEN)
		quic[5] = 8
		binary.LittleEndian.PutUint64(quic[6:], rand.Uint64())
		quic[14] = 3
		copy(quic[15:18], packet[4:])
		XorInit(quic[qlen:], mask)
	case MessageResponseType:
		quic, qlen = AddQuicInitHeader(packet, QUIC_RESP_LEN)
		quic[5] = 3
		copy(quic[6:9], packet[8:])
		quic[9] = 3
		copy(quic[10:13], packet[4:])
		XorResp(quic[qlen:], mask)
	case MessageCookieReplyType:
		quic, qlen = AddQuicInitHeader(packet, QUIC_COOK_LEN)
		quic[5] = 3
		copy(quic[6:9], packet[4:])
		quic[9] = 0
		XorCook(quic[qlen:], mask)
	}

	XorHead(quic, device)
	return quic
}

package device

import (
	"encoding/binary"
	"math/rand/v2"
	"unsafe"
)

func uintSlice(buffer []byte, len int) []uint32 {
	return unsafe.Slice((*uint32)(unsafe.Pointer(&buffer[0])), len)
}

func maskLen(hlen byte, mask []byte) byte {
	return hlen ^ mask[7]
}

func xorHead(buffer []byte, mask []byte) {
	buffer[0] = (buffer[0] & 0xF0) | ((buffer[0] ^ mask[3]) & 0x0F)
}

func xorData(buffer []byte, mask []uint32) {
	ptr := uintSlice(buffer, 4)
	zero := ptr[0] ^ mask[0]
	ptr[1] ^= zero ^ mask[1]
	ptr[2] ^= zero ^ mask[2]
	ptr[3] ^= zero ^ mask[3]
}

func xorCook(buffer []byte, mask []uint32) {
	ptr := uintSlice(buffer, 2)
	zero := ptr[0] ^ mask[0]
	ptr[1] ^= zero ^ mask[1]
}

func xorInit(buffer []byte, mask []uint32) {
	ptr := uintSlice(buffer, 2)
	zero := ptr[0] ^ mask[0]
	ptr[1] ^= zero ^ mask[1]
	xorMac2(buffer, zero, mask)
}

func xorResp(buffer []byte, mask []uint32) {
	ptr := uintSlice(buffer, 3)
	zero := ptr[0] ^ mask[0]
	ptr[1] ^= zero ^ mask[1]
	ptr[2] ^= zero ^ mask[2]
	xorMac2(buffer, zero, mask)
}

func xorMac2(buffer []byte, zero uint32, mask []uint32) {
	ptr := uintSlice(buffer[len(buffer)-16:], 4)
	ptr[0] ^= zero ^ mask[4]
	ptr[1] ^= zero ^ mask[5]
	ptr[2] ^= zero ^ mask[6]
	ptr[3] ^= zero ^ mask[7]
}

func hiddenLen(val byte) int {
	return int(val & 31)
}

func quicHiddenLen(buffer []byte, qlen int, mask []byte) int {
	if buffer[0]&1 == 0 {
		return qlen
	}
	return qlen + int(maskLen(buffer[qlen], mask))
}

const (
	quicInitLen = 21
	quicRespLen = 16
	quicCookLen = 13
	quicDataLen = 4
)

func removeHidden(buffer []byte, device *Device) int {
	if len(buffer) < MinMessageSize {
		return -1
	}

	mask := device.staticIdentity.publicKey[:]
	xorHead(buffer, mask)
	msgType := uint32(0)
	hlen := int(0)

	if (buffer[0] & 0x80) == 0 {
		msgType = MessageTransportType
		if buffer[0]&1 == 1 {
			hlen = quicHiddenLen(buffer, quicDataLen, mask)
			buffer = buffer[hlen:]
		}
	} else {
		if buffer[5] != 3 {
			hlen = quicHiddenLen(buffer, quicInitLen, mask)
			msgType = MessageInitiationType
		} else if buffer[9] != 0 {
			hlen = quicHiddenLen(buffer, quicRespLen, mask)
			msgType = MessageResponseType
		} else {
			hlen = quicHiddenLen(buffer, quicCookLen, mask)
			msgType = MessageCookieReplyType
		}
		buffer = buffer[hlen:]
	}

	switch msgType {
	case MessageTransportType:
		xorData(buffer, uintSlice(mask, 8))
	case MessageInitiationType:
		xorInit(buffer, uintSlice(mask, 8))
	case MessageResponseType:
		xorResp(buffer, uintSlice(mask, 8))
	case MessageCookieReplyType:
		xorCook(buffer, uintSlice(mask, 8))
	default:
		return -1
	}

	binary.LittleEndian.PutUint32(buffer, msgType)

	return hlen
}

func addHiddenHeader(packet []byte, qlen int, hlen int) ([]byte, int) {
	tlen := qlen + hlen
	hidden := make([]byte, len(packet)+tlen)
	hlenNext := hidden[qlen:]
	hlenLeft := hlen
	for hlenLeft > 0 {
		binary.LittleEndian.PutUint64(hlenNext, rand.Uint64())
		hlenNext = hlenNext[8:]
		hlenLeft -= 8
	}
	copy(hidden[tlen:], packet)
	return hidden, tlen
}

func addQuicInitHeader(packet []byte, qlen int, mask []byte) ([]byte, int) {
	hlen := hiddenLen(byte(rand.Uint32()))
	quic, offset := addHiddenHeader(packet, qlen, hlen)
	if hlen > 0 {
		quic[0] = 0xC1 | byte(rand.Uint32()&0x0E)
		quic[qlen] = maskLen(byte(hlen), mask)
	} else {
		quic[0] = 0xC0 | byte(rand.Uint32()&0x0E)
	}
	binary.BigEndian.PutUint32(quic[1:], 1)
	quic[qlen-3] = 0
	binary.BigEndian.PutUint16(quic[qlen-2:], 0x4000|uint16(hlen+len(packet)))
	return quic, offset
}

func addQuicDataHeader(packet []byte, mask []byte) ([]byte, int) {
	hlen := max(1, hiddenLen(byte(rand.Uint32())))
	quic, offset := addHiddenHeader(packet, quicDataLen, hlen)
	quic[0] = 0x41 | byte(rand.Uint32()&0x1E)
	quic[quicDataLen] = maskLen(byte(hlen), mask)
	copy(quic[1:4], packet[4:])
	return quic, offset
}

func applyHidden(packet []byte, msgType uint32, peer *Peer) []byte {
	mask := peer.handshake.remoteStatic[:]

	if msgType == MessageTransportType && len(packet) != MessageKeepaliveSize {
		packet[0] = (byte(rand.Uint32()) & 0x1E) | 0x40
		copy(packet[1:4], packet[4:])
		xorData(packet, uintSlice(mask, 8))
		xorHead(packet, mask)
		return packet
	}

	binary.LittleEndian.PutUint32(packet, rand.Uint32())
	quic := packet
	qlen := 0

	switch msgType {
	case MessageTransportType:
		quic, qlen = addQuicDataHeader(packet, mask)
		xorData(quic[qlen:], uintSlice(mask, 8))
	case MessageInitiationType:
		quic, qlen = addQuicInitHeader(packet, quicInitLen, mask)
		quic[5] = 8
		binary.LittleEndian.PutUint64(quic[6:], rand.Uint64())
		quic[14] = 3
		copy(quic[15:18], packet[4:])
		xorInit(quic[qlen:], uintSlice(mask, 8))
	case MessageResponseType:
		quic, qlen = addQuicInitHeader(packet, quicRespLen, mask)
		quic[5] = 3
		copy(quic[6:9], packet[8:])
		quic[9] = 3
		copy(quic[10:13], packet[4:])
		xorResp(quic[qlen:], uintSlice(mask, 8))
	case MessageCookieReplyType:
		quic, qlen = addQuicInitHeader(packet, quicCookLen, mask)
		quic[5] = 3
		copy(quic[6:9], packet[4:])
		quic[9] = 0
		xorCook(quic[qlen:], uintSlice(mask, 8))
	}

	xorHead(quic, mask)
	return quic
}

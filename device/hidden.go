package device

import (
	"encoding/binary"
	"math/rand/v2"
	"unsafe"
)

func uintSlice(buffer []byte, len int) []uint32 {
	return unsafe.Slice((*uint32)(unsafe.Pointer(&buffer[0])), len)
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
	return int(val & 7)
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

	xorHead(buffer, device.staticIdentity.publicKey[:])
	msgType := uint32(0)
	hlen := hiddenLen(buffer[0])

	if (buffer[0] & 0x80) != 0 {
		if buffer[5] != 3 {
			hlen += quicInitLen
			msgType = MessageInitiationType
		} else if buffer[9] != 0 {
			hlen += quicRespLen
			msgType = MessageResponseType
		} else {
			hlen += quicCookLen
			msgType = MessageCookieReplyType
		}
		buffer = buffer[hlen:]
	} else {
		msgType = MessageTransportType
		if hlen > 0 {
			hlen += quicDataLen
			buffer = buffer[hlen:]
		}
	}

	mask := uintSlice(device.staticIdentity.publicKey[:], 8)

	switch msgType {
	case MessageTransportType:
		xorData(buffer, mask)
	case MessageInitiationType:
		xorInit(buffer, mask)
	case MessageResponseType:
		xorResp(buffer, mask)
	case MessageCookieReplyType:
		xorCook(buffer, mask)
	default:
		return -1
	}

	binary.LittleEndian.PutUint32(buffer, msgType)

	return hlen
}

func addHiddenHeader(packet []byte, qlen int, hlen int) ([]byte, int) {
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

func addQuicInitHeader(packet []byte, qlen int) ([]byte, int) {
	flags := 0xC0 | byte(rand.Uint32()&0x0F)
	hlen := hiddenLen(flags)
	quic, offset := addHiddenHeader(packet, qlen, hlen)
	quic[0] = flags
	binary.BigEndian.PutUint32(quic[1:], 1)
	quic[qlen-3] = 0
	binary.BigEndian.PutUint16(quic[qlen-2:], 0x4000|uint16(hlen+len(packet)))
	return quic, offset
}

func addQuicDataHeader(packet []byte) ([]byte, int) {
	flags := 0x40 | byte(rand.Uint32()&0x1F)
	quic, offset := addHiddenHeader(packet, quicDataLen, hiddenLen(flags))
	quic[0] = flags
	copy(quic[1:4], packet[4:])
	return quic, offset
}

func applyHidden(packet []byte, msgType uint32, peer *Peer) []byte {
	mask := uintSlice(peer.handshake.remoteStatic[:], 8)

	if msgType == MessageTransportType && len(packet) != MessageKeepaliveSize {
		packet[0] = (byte(rand.Uint32()) & 0x18) | 0x40
		copy(packet[1:4], packet[4:])
		xorData(packet, mask)
		xorHead(packet, peer.handshake.remoteStatic[:])
		return packet
	}

	binary.LittleEndian.PutUint32(packet, rand.Uint32())
	quic := packet
	qlen := 0

	switch msgType {
	case MessageTransportType:
		quic, qlen = addQuicDataHeader(packet)
		xorData(quic[qlen:], mask)
	case MessageInitiationType:
		quic, qlen = addQuicInitHeader(packet, quicInitLen)
		quic[5] = 8
		binary.LittleEndian.PutUint64(quic[6:], rand.Uint64())
		quic[14] = 3
		copy(quic[15:18], packet[4:])
		xorInit(quic[qlen:], mask)
	case MessageResponseType:
		quic, qlen = addQuicInitHeader(packet, quicRespLen)
		quic[5] = 3
		copy(quic[6:9], packet[8:])
		quic[9] = 3
		copy(quic[10:13], packet[4:])
		xorResp(quic[qlen:], mask)
	case MessageCookieReplyType:
		quic, qlen = addQuicInitHeader(packet, quicCookLen)
		quic[5] = 3
		copy(quic[6:9], packet[4:])
		quic[9] = 0
		xorCook(quic[qlen:], mask)
	}

	xorHead(quic, peer.handshake.remoteStatic[:])
	return quic
}

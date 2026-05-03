package device

func AddHiddenHeader(packet []byte, msgType uint32) []byte {
	hidden := make([]byte, len(packet)+2)
	copy(hidden[2:], packet[0:])
	hidden[0] = 1
	hidden[1] = byte(msgType)
	return hidden
}

func HiddenHeaderLen(val byte) uint8 {
	return 1 + (val & 3)
}

func MsgHiddenType(val uint32) uint32 {
	return val & 7
}

func HiddenType(val uint32) uint32 {
	return val
}

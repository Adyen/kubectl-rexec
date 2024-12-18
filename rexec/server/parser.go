package server

import (
	"encoding/binary"
	"errors"
)

type webSocketFrame struct {
	Fin     bool
	Opcode  byte
	Mask    bool
	Payload []byte
}

// parseWebSocketFrame is for parsing websocket traffic
func parseWebSocketFrame(data []byte) (*webSocketFrame, error) {
	if len(data) < 2 {
		return nil, errors.New("data too short to be a WebSocket frame")
	}

	fin := data[0]&0x80 != 0
	opcode := data[0] & 0x0F

	mask := data[1]&0x80 != 0
	payloadLen := int(data[1] & 0x7F)

	var offset int
	switch payloadLen {
	case 126:
		if len(data) < 4 {
			return nil, errors.New("data too short for extended payload length")
		}
		payloadLen = int(binary.BigEndian.Uint16(data[2:4]))
		offset = 4
	case 127:
		if len(data) < 10 {
			return nil, errors.New("data too short for extended payload length")
		}
		payloadLen = int(binary.BigEndian.Uint64(data[2:10]))
		offset = 10
	default:
		offset = 2
	}

	if mask {
		offset += 4
	}

	var maskingKey []byte
	if mask {
		maskingKey = data[offset-4 : offset]
	}

	payload := data[offset:]

	if mask {
		for i := 0; i < len(payload); i++ {
			payload[i] ^= maskingKey[i%4]
		}
	}

	return &webSocketFrame{
		Fin:     fin,
		Opcode:  opcode,
		Mask:    mask,
		Payload: payload,
	}, nil
}

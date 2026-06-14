package server

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildFrame assembles a WebSocket frame. When mask is true the payload is
// masked with maskKey, mirroring how a kubectl client frames terminal input.
func buildFrame(opcode byte, payload []byte, mask bool, maskKey [4]byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(0x80 | opcode) // FIN set

	n := len(payload)
	switch {
	case n < 126:
		b := byte(n)
		if mask {
			b |= 0x80
		}
		buf.WriteByte(b)
	case n < 65536:
		b := byte(126)
		if mask {
			b |= 0x80
		}
		buf.WriteByte(b)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(n))
		buf.Write(ext[:])
	default:
		b := byte(127)
		if mask {
			b |= 0x80
		}
		buf.WriteByte(b)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		buf.Write(ext[:])
	}

	if mask {
		buf.Write(maskKey[:])
		masked := make([]byte, n)
		for i := range payload {
			masked[i] = payload[i] ^ maskKey[i%4]
		}
		buf.Write(masked)
	} else {
		buf.Write(payload)
	}

	return buf.Bytes()
}

func TestParseWebSocketFrame(t *testing.T) {
	key := [4]byte{0xAA, 0xBB, 0xCC, 0xDD}

	tests := []struct {
		name        string
		data        []byte
		wantOpcode  byte
		wantPayload []byte
		wantErr     bool
	}{
		{
			name:        "unmasked text frame",
			data:        buildFrame(0x1, []byte("hello"), false, key),
			wantOpcode:  0x1,
			wantPayload: []byte("hello"),
		},
		{
			name:        "masked binary frame",
			data:        buildFrame(0x2, []byte("ls -la"), true, key),
			wantOpcode:  0x2,
			wantPayload: []byte("ls -la"),
		},
		{
			name:        "empty payload",
			data:        buildFrame(0x2, []byte{}, true, key),
			wantOpcode:  0x2,
			wantPayload: []byte{},
		},
		{
			name:        "extended 16-bit length",
			data:        buildFrame(0x2, bytes.Repeat([]byte("a"), 300), true, key),
			wantOpcode:  0x2,
			wantPayload: bytes.Repeat([]byte("a"), 300),
		},
		{
			name:        "extended 64-bit length",
			data:        buildFrame(0x2, bytes.Repeat([]byte("b"), 70000), true, key),
			wantOpcode:  0x2,
			wantPayload: bytes.Repeat([]byte("b"), 70000),
		},
		{
			name:    "too short for header",
			data:    []byte{0x82},
			wantErr: true,
		},
		{
			name:    "truncated extended 16-bit header",
			data:    []byte{0x82, 126, 0x00},
			wantErr: true,
		},
		{
			name:    "truncated masking key",
			data:    []byte{0x82, 0x85, 0xAA, 0xBB}, // masked, len 5, only 2 of 4 key bytes
			wantErr: true,
		},
		{
			name:    "payload shorter than declared",
			data:    []byte{0x82, 0x05, 'h', 'i'}, // declares 5, has 2
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			original := append([]byte(nil), tt.data...)

			frame, consumed, err := parseWebSocketFrame(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got frame %+v", frame)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if frame.Opcode != tt.wantOpcode {
				t.Errorf("opcode = %#x, want %#x", frame.Opcode, tt.wantOpcode)
			}
			if !bytes.Equal(frame.Payload, tt.wantPayload) {
				t.Errorf("payload = %q, want %q", frame.Payload, tt.wantPayload)
			}
			if consumed != len(tt.data) {
				t.Errorf("consumed = %d, want %d", consumed, len(tt.data))
			}
			if !bytes.Equal(tt.data, original) {
				t.Errorf("input buffer was mutated: got %v, want %v", tt.data, original)
			}
		})
	}
}

func TestParseWebSocketFrameCoalesced(t *testing.T) {
	key := [4]byte{0x01, 0x02, 0x03, 0x04}
	first := buildFrame(0x2, []byte("echo"), true, key)
	second := buildFrame(0x2, []byte("date"), true, key)
	buf := append(append([]byte(nil), first...), second...)

	frame1, consumed1, err := parseWebSocketFrame(buf)
	if err != nil {
		t.Fatalf("first frame: %v", err)
	}
	if !bytes.Equal(frame1.Payload, []byte("echo")) {
		t.Fatalf("first payload = %q, want %q", frame1.Payload, "echo")
	}
	if consumed1 != len(first) {
		t.Fatalf("first consumed = %d, want %d", consumed1, len(first))
	}

	frame2, consumed2, err := parseWebSocketFrame(buf[consumed1:])
	if err != nil {
		t.Fatalf("second frame: %v", err)
	}
	if !bytes.Equal(frame2.Payload, []byte("date")) {
		t.Fatalf("second payload = %q, want %q", frame2.Payload, "date")
	}
	if consumed2 != len(second) {
		t.Fatalf("second consumed = %d, want %d", consumed2, len(second))
	}
}

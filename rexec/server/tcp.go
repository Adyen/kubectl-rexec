package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/moby/spdystream/spdy"
	"github.com/rs/zerolog"
)

const (
	targetAddress = "kubernetes.default.svc.cluster.local:443"
)

func tcpForwarder(ctx context.Context) {
	lc := net.ListenConfig{}

	ctxid := ctx.Value(ctxSessionIDKey).(string)
	proto := protocolWebSocket
	if val := ctx.Value(ctxProtocolKey); val != nil {
		if parsed, ok := val.(protocolType); ok {
			proto = parsed
		}
	}
	socketPath := fmt.Sprintf("/%s", ctxid)

	// we setup a unix listener for the specific session
	listener, err := lc.Listen(ctx, "unix", socketPath)
	if err != nil {
		SysLogger.Error().Err(err).Msgf("failed to start listener for %s", ctxid)
		return
	}
	defer listener.Close()

	SysLogger.Debug().Msgf("starting personal tcp forwarer at %s", socketPath)

	// in a cheap manner we signer back that it is ready
	mapSync.Lock()
	proxyMap[ctxid] = true
	mapSync.Unlock()
	halt := false
	for {
		client, err := listener.Accept()
		if err != nil {
			SysLogger.Error().Err(err).Msgf("failed to accept connection at %s", ctxid)
			continue
		}

		// we pass the actual tcp connection
		go handleTcpConnection(client, ctxid, proto)
		select {
		// once the http session is gone we stop the listener
		case <-ctx.Done():
			SysLogger.Debug().Msgf("stopping personal tcp forwarer at %s", socketPath)
			halt = true
		}
		if halt {
			break
		}
	}
	// once the http session is gone, the socket and the user and proxymaps are getting cleaned up
	os.Remove(socketPath)
	mapSync.Lock()
	delete(proxyMap, ctxid)
	delete(userMap, ctxid)
	mapSync.Unlock()

	commandSync.Lock()
	delete(commandMap, ctxid)
	commandSync.Unlock()
}

func handleTcpConnection(client net.Conn, ctxid string, proto protocolType) {
	// setting up the upstream connection
	target, err := tls.Dial("tcp", targetAddress, &tls.Config{RootCAs: CAPool})
	if err != nil {
		SysLogger.Error().Err(err).Msgf("failed to connect to upstream at %s", ctxid)
		client.Close()
		return
	}
	defer target.Close()

	// we are creating an instance of TCPLogger
	// which implements net.conn and custom logging
	// with the context of the user we are logging
	// traffic for
	tcpLogger := newTCPLogger(target, ctxid, proto)
	defer tcpLogger.CloseParsers()

	// on the way toward the target we send the traffic
	// through the tcp logger
	go io.Copy(tcpLogger, client)
	// on the way back however we dont want to log anything
	io.Copy(client, target)
	client.Close()
}

type TCPLogger struct {
	net.Conn
	ctxid                 string
	protocol              protocolType
	wsBuffer              []byte
	wsHandshakeComplete   bool
	spdyFramer            *spdy.Framer
	spdyPipeW             *io.PipeWriter
	spdyPipeR             *io.PipeReader
	spdyHandshakeBuf      []byte
	spdyHandshakeComplete bool
	spdyStreams           map[spdy.StreamId]string
	spdyMutex             sync.Mutex
}

func (t *TCPLogger) Read(b []byte) (n int, err error) {
	n, err = t.Conn.Read(b)
	return
}

func (t *TCPLogger) Write(b []byte) (n int, err error) {
	switch t.protocol {
	case protocolWebSocket:
		t.handleWebsocketBytes(b)
	case protocolSPDY:
		t.handleSpdyBytes(b)
	}
	return t.Conn.Write(b)
}

func (t *TCPLogger) CloseParsers() {
	if t.spdyPipeW != nil {
		t.spdyPipeW.Close()
	}
	if t.spdyPipeR != nil {
		t.spdyPipeR.Close()
	}
}

func newTCPLogger(conn net.Conn, ctxid string, proto protocolType) *TCPLogger {
	logger := &TCPLogger{
		Conn:     conn,
		ctxid:    ctxid,
		protocol: proto,
	}
	if proto == protocolSPDY {
		reader, writer := io.Pipe()
		framer, err := spdy.NewFramer(io.Discard, bufio.NewReader(reader))
		if err != nil {
			SysLogger.Error().Err(err).Msg("failed to create SPDY framer")
			return logger
		}
		logger.spdyFramer = framer
		logger.spdyPipeR = reader
		logger.spdyPipeW = writer
		logger.spdyStreams = map[spdy.StreamId]string{}
		go logger.consumeSpdyFrames()
	}
	return logger
}

func (t *TCPLogger) handleWebsocketBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	t.wsBuffer = append(t.wsBuffer, b...)

	if !t.wsHandshakeComplete {
		if idx := bytes.Index(t.wsBuffer, []byte("\r\n\r\n")); idx >= 0 {
			t.wsBuffer = t.wsBuffer[idx+4:]
			t.wsHandshakeComplete = true
		} else {
			// avoid unbounded growth during handshake
			if len(t.wsBuffer) > 8192 {
				t.wsBuffer = t.wsBuffer[len(t.wsBuffer)-8192:]
			}
			return
		}
	}

	for len(t.wsBuffer) > 0 {
		frame, consumed, err := parseWebSocketFrame(t.wsBuffer)
		if err != nil {
			if errors.Is(err, errIncompleteFrame) {
				return
			}
			SysLogger.Debug().Err(err).Msg("failed to parse websocket frame")
			return
		}
		if frame != nil && frame.Opcode == 0x2 {
			t.publishAudit(frame.Payload)
		}
		t.wsBuffer = t.wsBuffer[consumed:]
	}
}

func (t *TCPLogger) handleSpdyBytes(b []byte) {
	if t.spdyPipeW == nil || len(b) == 0 {
		return
	}

	if !t.spdyHandshakeComplete {
		t.spdyHandshakeBuf = append(t.spdyHandshakeBuf, b...)
		if idx := bytes.Index(t.spdyHandshakeBuf, []byte("\r\n\r\n")); idx >= 0 {
			t.spdyHandshakeComplete = true
			remaining := t.spdyHandshakeBuf[idx+4:]
			t.spdyHandshakeBuf = nil
			if len(remaining) > 0 {
				t.writeToSpdyParser(remaining)
			}
		}
		return
	}

	t.writeToSpdyParser(b)
}

func (t *TCPLogger) writeToSpdyParser(b []byte) {
	if t.spdyPipeW == nil || len(b) == 0 {
		return
	}
	if _, err := t.spdyPipeW.Write(b); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		SysLogger.Debug().Err(err).Msg("failed to feed SPDY parser")
	}
}

func (t *TCPLogger) consumeSpdyFrames() {
	if t.spdyFramer == nil {
		return
	}
	for {
		frame, err := t.spdyFramer.ReadFrame()
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
				SysLogger.Debug().Err(err).Msg("SPDY parser stopped")
			}
			return
		}
		switch f := frame.(type) {
		case *spdy.SynStreamFrame:
			streamType := strings.ToLower(f.Headers.Get("streamtype"))
			if streamType == "" {
				streamType = strings.ToLower(f.Headers.Get("stream-type"))
			}
			if streamType != "" {
				t.spdyMutex.Lock()
				t.spdyStreams[f.StreamId] = streamType
				t.spdyMutex.Unlock()
			}
		case *spdy.DataFrame:
			t.spdyMutex.Lock()
			streamType := t.spdyStreams[f.StreamId]
			t.spdyMutex.Unlock()
			if streamType == "stdin" {
				t.publishAudit(f.Data)
			}
		}
	}
}

func (t *TCPLogger) publishAudit(payload []byte) {
	if len(payload) == 0 {
		return
	}
	if auditLogger.GetLevel() == zerolog.TraceLevel {
		stroke, err := hex.DecodeString(fmt.Sprintf("%x", payload))
		if err != nil {
			SysLogger.Error().Err(err).Msg("failed to parse payload")
		} else {
			auditLogger.Trace().Str("user", userMap[t.ctxid]).Str("session", t.ctxid).Str("stroke", strings.ReplaceAll(string(stroke), "\u0000", "")).Msg("")
		}
	}
	asyncAuditChan <- asyncAudit{
		ctxid: t.ctxid,
		ascii: payload,
	}
}

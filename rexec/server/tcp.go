package server

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/rs/zerolog"
)

const (
	targetAddress = "kubernetes.default.svc.cluster.local:443"
)

func tcpForwarder(ctx context.Context) {
	lc := net.ListenConfig{}

	ctxid := ctx.Value("sessionID").(string)
	socketPath := fmt.Sprintf("/%s", ctxid)

	// we setup a unix listener for the specific session
	listener, err := lc.Listen(ctx, "unix", socketPath)
	if err != nil {
		SysLogger.Error().Err(err).Msgf("failed to start listener for %d", ctxid)
		return
	}
	defer listener.Close()

	SysLogger.Debug().Msgf("starting personal tcp forwarer at " + socketPath)

	// in a cheap manner we signer back that it is ready
	mapSync.Lock()
	proxyMap[ctxid] = true
	mapSync.Unlock()
	halt := false
	for {
		client, err := listener.Accept()
		if err != nil {
			SysLogger.Error().Err(err).Msgf("failed to accept connection at %d", ctxid)
			continue
		}

		// we pass the actual tcp connection
		go handleTcpConnection(client, ctxid)
		select {
		// once the http session is gone we stop the listener
		case <-ctx.Done():
			SysLogger.Debug().Msgf("stopping personal tcp forwarer at " + socketPath)
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

func handleTcpConnection(client net.Conn, ctxid string) {
	// setting up the upstream connection
	target, err := tls.Dial("tcp", targetAddress, &tls.Config{RootCAs: CAPool})
	if err != nil {
		SysLogger.Error().Err(err).Msgf("failed to connect to upstream at %d", ctxid)
		client.Close()
		return
	}
	defer target.Close()

	// we are creating an instance of TCPLogger
	// which implements net.conn and custom logging
	// with the context of the user we are logging
	// traffic for
	tcpLogger := &TCPLogger{Conn: target, ctxid: ctxid}

	// on the way toward the target we send the traffic
	// through the tcp logger
	go io.Copy(tcpLogger, client)
	// on the way back however we dont want to log anything
	io.Copy(client, target)
	client.Close()
}

type TCPLogger struct {
	net.Conn
	ctxid string
}

func (t *TCPLogger) Read(b []byte) (n int, err error) {
	n, err = t.Conn.Read(b)
	return
}

func (t *TCPLogger) Write(b []byte) (n int, err error) {
	n, err = t.Conn.Write(b)
	if n > 0 {
		// we need parse the websockter frame
		frame, err := parseWebSocketFrame(b)
		if err != nil {
			SysLogger.Error().Err(err).Msg("failed to parse ws frame")
		}
		if frame != nil {
			// if it is opscode 0x2 we log out
			// activities
			if frame.Opcode == 0x2 {
				if auditLogger.GetLevel() == zerolog.TraceLevel {
					stroke, err := hex.DecodeString(fmt.Sprintf("%x", frame.Payload))
					SysLogger.Error().Err(err).Msg("failed to parse payload")

					auditLogger.Trace().Str("user", userMap[t.ctxid]).Str("session", t.ctxid).Str("stroke", strings.ReplaceAll(string(stroke), "\u0000", "")).Msg("")
					asyncAuditChan <- asyncAudit{
						ctxid: t.ctxid,
						ascii: frame.Payload,
					}
				}

			}
		}
	}
	return
}

package server

import (
	"crypto/x509"
	"os"
	"sync"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

var (
	caPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	exitFn    = os.Exit // to be able to override in the tests
)

var token string
var proxyMap map[string]bool
var userMap map[string]string
var mapSync sync.Mutex
var SysLogger zerolog.Logger
var auditLogger zerolog.Logger
var SysDebugLog bool
var AuditFullTraceLog bool
var CAPool *x509.CertPool
var asyncAuditChan chan asyncAudit
var commandMap map[string][]byte
var commandSync sync.Mutex
var SecretSauce string
var ByPassedUsers []string
var MaxStokesPerLine int

func Init() {
	auditLevel := zerolog.InfoLevel
	if AuditFullTraceLog {
		auditLevel = zerolog.TraceLevel
	}
	sysLevel := zerolog.PanicLevel
	if SysDebugLog {
		sysLevel = zerolog.DebugLevel
	}
	auditLogger = zerolog.New(os.Stdout).With().Timestamp().Str("facility", "audit").Logger().Level(auditLevel)
	SysLogger = zerolog.New(os.Stdout).With().Timestamp().Str("facility", "sys").Logger().Level(sysLevel)

	rawCaCert, err := os.ReadFile(caPath)
	if err != nil {
		SysLogger.Error().Err(err).Msg("failed to read the CA certificate")
		exitFn(1)
		return
	}
	CAPool = x509.NewCertPool()
	CAPool.AppendCertsFromPEM(rawCaCert)
	rawToken, err := os.ReadFile(tokenPath)
	if err != nil {
		SysLogger.Error().Err(err).Msg("failed to read the service account token")
		exitFn(1)
		return
	}
	token = string(rawToken)
	proxyMap = make(map[string]bool)
	userMap = make(map[string]string)
	commandMap = make(map[string][]byte)
	asyncAuditChan = make(chan asyncAudit)

	if SecretSauce == "" {
		SecretSauce = uuid.New().String()
	}
	if SecretSauce != "" {
		_, err = uuid.Parse(SecretSauce)
		if err != nil {
			SysLogger.Error().Err(err).Msg("SecretSauce does not contain a valid UUID")
			exitFn(1)
			return
		}
	}
	if MaxStokesPerLine == 0 {
		MaxStokesPerLine = 2000
	}

	go asyncAuditor()
}

func logCommand(command, user, ctxid string) {
	auditLogger.Info().Str("user", user).Str("session", ctxid).Str("command", command).Msg("")
}

var httpSpec = `
{
  "kind": "APIResourceList",
  "apiVersion": "v1",
  "groupVersion": "audit.adyen.internal/v1beta1",
  "resources": []
}
`

var httpForbidden = `
No User found
`

var httpInternalError = `
Internal errror
`

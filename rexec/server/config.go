package server

import (
	"crypto/x509"
	"os"
	"sync"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
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
	var sysLogLevel zerolog.Level
	sysLogLevel = zerolog.FatalLevel
	if SysDebugLog {
		sysLogLevel = zerolog.DebugLevel
	}

	var auditLogLevel zerolog.Level
	auditLogLevel = zerolog.InfoLevel
	if AuditFullTraceLog {
		auditLogLevel = zerolog.TraceLevel
	}

	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()

	SysLogger = logger.With().Str("facility", "sys").Logger().Level(sysLogLevel)
	auditLogger = logger.With().Str("facility", "audit").Logger().Level(auditLogLevel)
	rawCaCert, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		logger.Fatal().Err(err)
	}
	CAPool = x509.NewCertPool()
	CAPool.AppendCertsFromPEM(rawCaCert)
	rawToken, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		logger.Fatal().Err(err)
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
			logger.Fatal().Err(err)
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

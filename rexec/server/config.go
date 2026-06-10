package server

import (
	"crypto/x509"
	"os"
	"sync"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

var (
	caPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	exitFn    = os.Exit // to be able to override in the tests
)

type sessionInfo struct {
	User      string
	NameSpace string
	Pod       string
	Container string
	ClientIP  string
}

var token string
var sessionMap map[string]sessionInfo
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
var tokenSync sync.Mutex

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
	err = loadToken()
	if err != nil {
		SysLogger.Error().Err(err).Msg("failed to load the service account token")
		exitFn(1)
		return
	}
	sessionMap = make(map[string]sessionInfo)
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

	// load the front-proxy CA so inbound exec requests can be authenticated as
	// genuinely coming from the kube-apiserver aggregation layer before we trust
	// their impersonation headers. fail closed if it cannot be loaded.
	if err = loadFrontProxyConfig(); err != nil {
		SysLogger.Error().Err(err).Msg("failed to load the front-proxy (requestheader) configuration")
		exitFn(1)
		return
	}

	go asyncAuditor()
}

func parseToken() (jwt.MapClaims, error) {
	// we do not need to do any actual validation on this jwt, as it will be validated by k8s api server
	// anyway, so we just parse it and return the claims, so we can check the expiration time
	token, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{}) // nosonar
	if err != nil {
		return nil, err
	}
	return token.Claims.(jwt.MapClaims), nil
}

func loadToken() error {
	rawToken, err := os.ReadFile(tokenPath)
	if err != nil {
		return err
	}
	token = string(rawToken)
	return nil
}

func logCommand(command, user, ctxid, namespace, pod, container, clientIP string) {
	auditLogger.Info().Str("user", user).Str("session", ctxid).Str("namespace", namespace).Str("pod", pod).Str("container", container).Str("client_ip", clientIP).Str("command", command).Msg("")
}

func logSessionEvent(event, user, ctxid, namespace, pod, container, clientIP string) {
	auditLogger.Info().Str("event", event).Str("user", user).Str("session", ctxid).Str("namespace", namespace).Str("pod", pod).Str("container", container).Str("client_ip", clientIP).Msg("")
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

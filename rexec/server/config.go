package server

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	klog "k8s.io/klog/v2"
	"k8s.io/klog/v2/textlogger"
)

const (
	authConfigMapNamespace       = "kube-system"
	authConfigMapName            = "extension-apiserver-authentication"
	requestHeaderCAKey           = "requestheader-client-ca-file"
	requestHeaderAllowedNamesKey = "requestheader-allowed-names"
)

var (
	caPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	exitFn    = os.Exit // to be able to override in the tests
)

// RequestHeaderCAPool holds the front-proxy CA the kube-apiserver uses to sign
// the client certificate it presents when proxying aggregated API traffic.
// Inbound exec requests must present a certificate chaining to this pool before
// their X-Remote-* identity headers may be trusted.
var RequestHeaderCAPool *x509.CertPool

// RequestHeaderAllowedNames is the list of client-certificate common names the
// kube-apiserver is allowed to present. An empty list means any name validated
// by RequestHeaderCAPool is accepted, matching kube-apiserver behaviour.
var RequestHeaderAllowedNames []string

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

var ingressDiscardLog = textlogger.NewLogger(textlogger.NewConfig(textlogger.Output(io.Discard)))

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

	initAPIServer()

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

// ingressLogContext silences klog/logr noise from k8s.io/streaming on websocket disconnect
func ingressLogContext(ctx context.Context) context.Context {
	if SysDebugLog {
		return ctx
	}
	return klog.NewContext(ctx, ingressDiscardLog)
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

// loadFrontProxyConfig reads the requestheader CA and allowed client-certificate
// common names from the kube-system extension-apiserver-authentication ConfigMap.
// The kube-apiserver publishes there the CA it uses to sign the proxy client
// certificate. An aggregated API server must verify inbound client certificates
// against this CA before trusting the X-Remote-User / X-Remote-Group headers,
// otherwise any caller able to reach the backend directly can forge them and
// have the server impersonate an arbitrary user (e.g. system:masters).
func loadFrontProxyConfig() error {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to build in-cluster config: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to build kubernetes client: %w", err)
	}
	cm, err := clientset.CoreV1().ConfigMaps(authConfigMapNamespace).Get(context.Background(), authConfigMapName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to read %s/%s: %w", authConfigMapNamespace, authConfigMapName, err)
	}

	caPEM, ok := cm.Data[requestHeaderCAKey]
	if !ok || caPEM == "" {
		return fmt.Errorf("%s missing from %s/%s", requestHeaderCAKey, authConfigMapNamespace, authConfigMapName)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return errors.New("failed to parse requestheader client CA certificate")
	}
	RequestHeaderCAPool = pool

	if raw, ok := cm.Data[requestHeaderAllowedNamesKey]; ok && raw != "" {
		var names []string
		if err := json.Unmarshal([]byte(raw), &names); err != nil {
			return fmt.Errorf("failed to parse %s: %w", requestHeaderAllowedNamesKey, err)
		}
		RequestHeaderAllowedNames = names
	}
	return nil
}

func logCommand(command, user, ctxid, namespace, pod, container, clientIP string) {
	auditLogger.Info().Str("user", user).Str("session", ctxid).Str("namespace", namespace).Str("pod", pod).Str("container", container).Str("client_ip", clientIP).Str("command", command).Msg("")
}

func logSessionEvent(event, user, ctxid, namespace, pod, container, clientIP string) {
	auditLogger.Info().Str("event", event).Str("user", user).Str("session", ctxid).Str("namespace", namespace).Str("pod", pod).Str("container", container).Str("client_ip", clientIP).Msg("")
}

func logIngress(protocol string) {
	auditLogger.Info().Str("event", "ingress").Str("protocol", protocol).Msg("")
}

func logEgress(protocol string) {
	auditLogger.Info().Str("event", "egress").Str("protocol", protocol).Msg("")
}

func logKeystroke(b byte, user, ctxid, namespace, pod, container, clientIP string) {
	auditLogger.Trace().
		Str("event", "keystroke").
		Str("user", user).Str("session", ctxid).
		Str("namespace", namespace).Str("pod", pod).Str("container", container).
		Str("client_ip", clientIP).
		Int("byte", int(b)).
		Bytes("ascii", []byte{b}).
		Msg("")
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

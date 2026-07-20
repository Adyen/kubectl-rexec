package server

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type rexecRequest struct {
	namespace string
	pod       string
	user      string
}

type rexecExecParams struct {
	command       []string
	needsRecording bool
	container     string
	clientIP      string
}

func Server() {
	// creating a mux router
	r := mux.NewRouter()

	// handling rexec request to handler
	r.HandleFunc("/apis/audit.adyen.internal/v1beta1/namespaces/{namespace}/pods/{pod}/exec", instrumentHandler("rexec", rexecHandler))
	// returning some dummy json making kubeapiserver happier
	r.HandleFunc("/apis/audit.adyen.internal/v1beta1", instrumentHandler("discovery", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(httpSpec)); err != nil {
			SysLogger.Error().Err(err).Msg("failed to write response")
		}
	}))
	// handle native pod exec through a validating webhook
	r.HandleFunc("/validate-exec", instrumentHandler("webhook", execHandler))

	// start tls listener.
	//
	// ClientCAs is the front-proxy (requestheader) CA published by the
	// kube-apiserver. VerifyClientCertIfGiven makes the handshake validate any
	// client certificate presented against it, so rexecHandler can require a
	// verified front-proxy identity before trusting impersonation headers. We do
	// not RequireAndVerifyClientCert at the listener because the admission
	// webhook (/validate-exec) is served on the same port and the apiserver does
	// not necessarily present a requestheader certificate when calling it.
	srv := &http.Server{
		Addr:    ":8443",
		Handler: r,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ClientCAs:  RequestHeaderCAPool,
			ClientAuth: tls.VerifyClientCertIfGiven,
		},
	}
	if err := srv.ListenAndServeTLS("/etc/pki/rexec/tls.crt", "/etc/pki/rexec/tls.key"); err != nil {
		SysLogger.Fatal().Err(err).Msg("rexec server terminated")
	}
}

// rexecHandler is responsible for rewrite the request to an exec request
// and proxy it back to k8s api
func rexecHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer recordRexecSessionStatus(w)

	req, ok := validateRexecRequest(w, r)
	if !ok {
		return
	}

	if !prepareRexecProxyRequest(w, r, req) {
		return
	}

	execParams, ok := parseRexecExecParams(w, r)
	if !ok {
		return
	}

	proxy := buildRexecProxy(start)
	cmd := strings.Join(execParams.command, " ")
	if !execParams.needsRecording {
		serveOneoffRexecSession(w, r, proxy, req, execParams, cmd)
		return
	}

	serveRecordingRexecSession(w, r, proxy, req, execParams, cmd)
}

func recordRexecSessionStatus(w http.ResponseWriter) {
	statusCode := http.StatusInternalServerError
	if rec, ok := w.(*statusRecorder); ok {
		if rec.status == 0 {
			statusCode = http.StatusOK
		} else {
			statusCode = rec.status
		}
	}
	recordSession(statusCode)
}

func validateRexecRequest(w http.ResponseWriter, r *http.Request) (rexecRequest, bool) {
	if !verifiedFrontProxy(r) {
		recordError("front_proxy")
		SysLogger.Error().Str("client_ip", getIP(r)).Msg("rejected exec request: missing or untrusted front-proxy client certificate")
		w.WriteHeader(http.StatusUnauthorized)
		if _, err := w.Write([]byte(httpForbidden)); err != nil {
			SysLogger.Error().Err(err).Msg("failed to write forbidden response")
		}
		return rexecRequest{}, false
	}

	pathParams := mux.Vars(r)
	req := rexecRequest{
		namespace: pathParams["namespace"],
		pod:       pathParams["pod"],
		user:      r.Header.Get("X-Remote-User"),
	}
	if req.user == "" || req.namespace == "" || req.pod == "" {
		w.WriteHeader(http.StatusForbidden)
		if _, err := w.Write([]byte(httpForbidden)); err != nil {
			SysLogger.Error().Err(err).Msg("failed to write forbidden response")
		}
		return rexecRequest{}, false
	}

	return req, true
}

func prepareRexecProxyRequest(w http.ResponseWriter, r *http.Request, req rexecRequest) bool {
	r.Header.Add("Kubectl-Command", "kubectl exec")

	if err := ensureValidToken(); err != nil {
		recordError("token")
		SysLogger.Error().Err(err).Msg("failed to check the service account token")
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write([]byte(httpInternalError)); err != nil {
			SysLogger.Error().Err(err).Msg("failed to write internal error response")
		}
		return false
	}

	r.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	r.Header.Add("Impersonate-User", req.user)
	for _, group := range r.Header.Values("X-Remote-Group") {
		r.Header.Add("Impersonate-Group", group)
	}
	r.Header.Add("Impersonate-Extra-Secret-Sauce", SecretSauce)

	newPath := fmt.Sprintf("api/v1/namespaces/%s/pods/%s/exec", req.namespace, req.pod)
	oldPath := fmt.Sprintf("apis/audit.adyen.internal/v1beta1/namespaces/%s/pods/%s/exec", req.namespace, req.pod)
	r.URL.Path = strings.ReplaceAll(r.URL.Path, oldPath, newPath)
	r.URL.RawPath = strings.ReplaceAll(r.URL.RawPath, oldPath, newPath)
	r.Host = apiServerHost + ":443"
	return true
}

func parseRexecExecParams(w http.ResponseWriter, r *http.Request) (rexecExecParams, bool) {
	params, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		recordError("request_parse")
		w.WriteHeader(http.StatusInternalServerError)
		if _, writeErr := w.Write([]byte(httpInternalError)); writeErr != nil {
			SysLogger.Error().Err(writeErr).Msg("failed to write internal error response")
		}
		return rexecExecParams{}, false
	}

	command, needsRecording, container := parseParams(params)
	return rexecExecParams{
		command:        command,
		needsRecording: needsRecording,
		container:      container,
		clientIP:       getIP(r),
	}, true
}

func buildRexecProxy(start time.Time) *httputil.ReverseProxy {
	apiServerURL, _ := url.Parse("https://" + apiServerDial)
	proxy := httputil.NewSingleHostReverseProxy(apiServerURL)
	proxy.FlushInterval = -1
	proxy.ModifyResponse = func(*http.Response) error {
		recordSessionStart(time.Since(start))
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		recordError("proxy")
		SysLogger.Error().Err(err).Msg("reverse proxy error")
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
	}
	return proxy
}

func serveOneoffRexecSession(w http.ResponseWriter, r *http.Request, proxy *httputil.ReverseProxy, req rexecRequest, execParams rexecExecParams, cmd string) {
	activeSessions.WithLabelValues("oneoff").Inc()
	defer activeSessions.WithLabelValues("oneoff").Dec()
	proxy.Transport = apiServerTransport()
	logCommand(cmd, req.user, "oneoff", req.namespace, req.pod, execParams.container, execParams.clientIP)
	proxy.ServeHTTP(w, r)
}

func serveRecordingRexecSession(w http.ResponseWriter, r *http.Request, proxy *httputil.ReverseProxy, req rexecRequest, execParams rexecExecParams, cmd string) {
	activeSessions.WithLabelValues("recording").Inc()
	defer activeSessions.WithLabelValues("recording").Dec()

	ctxid := uuid.New().String()
	info := registerSession(ctxid, req.user, req.namespace, req.pod, execParams.container, execParams.clientIP)
	defer endSession(ctxid)

	logCommand(cmd, req.user, ctxid, req.namespace, req.pod, execParams.container, execParams.clientIP)
	proxy.Transport = auditedAPIServerTransport(ctxid, info)
	proxy.ServeHTTP(w, r)
}

func ensureValidToken() error {
	SysLogger.Debug().Msg("checking service account token")
	claims, err := parseToken()
	if err != nil {
		SysLogger.Error().Err(err).Msg("failed to check the service account token")
		return err
	}
	expirationTime, err := claims.GetExpirationTime()
	if err != nil {
		SysLogger.Error().Err(err).Msg("failed to get expiration time from service account token")
		return err
	}
	if expirationTime.Before(time.Now().Add(60 * time.Second)) {
		SysLogger.Debug().Msg("service account token is expired, getting a new one")
		tokenSync.Lock()
		err = loadToken()
		tokenSync.Unlock()
		if err != nil {
			SysLogger.Error().Err(err).Msg("failed to load service account token")
			return err
		}
		claims, err = parseToken()
		if err != nil {
			SysLogger.Error().Err(err).Msg("failed to parse the new service account token")
			return err
		}
		expirationTime, err = claims.GetExpirationTime()
		if err != nil {
			SysLogger.Error().Err(err).Msg("failed to get expiration time from the new service account token")
			return err
		}
		if expirationTime.Before(time.Now().Add(60 * time.Second)) {
			SysLogger.Error().Msg("new service account token is also expired")
			return errors.New("new service account token is also expired")
		}
	}
	return nil
}

// execHandler is responsible for auditing exec request and allowing
// the ones coming through rexec api along with allowlisted users
func execHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "Invalid content type", http.StatusUnsupportedMediaType)
		return
	}

	var admissionReview admissionv1.AdmissionReview
	if err := json.NewDecoder(r.Body).Decode(&admissionReview); err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode request: %v", err), http.StatusBadRequest)
		return
	}

	response := admissionv1.AdmissionResponse{
		UID: admissionReview.Request.UID,
	}

	canPass := canPass(admissionReview)

	if admissionReview.Request.Kind.Kind == "PodExecOptions" {
		response.Allowed = canPass
		if canPass {
			webhookDecisionsTotal.WithLabelValues("allowed").Inc()
		} else {
			webhookDecisionsTotal.WithLabelValues("denied").Inc()
		}
		if !canPass {
			response.Result = &metav1.Status{
				Message: "cannot use exec directly, use rexec plugin instead",
			}
		}
	} else {
		response.Allowed = true
	}
	admissionReview.Response = &response
	respBytes, err := json.Marshal(admissionReview)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(respBytes); err != nil {
		SysLogger.Error().Err(err).Msg("failed to write admission response")
	}
}

// canPass checks whether the exec request is allowed
// or not
func canPass(rv admissionv1.AdmissionReview) bool {
	// check for users that have a bypass for validating
	for _, user := range ByPassedUsers {
		if user == rv.Request.UserInfo.Username {
			return true
		}
	}

	// we will check for a shared key so we can validate the request was
	// coming through the rexec endpoint
	sauce, ok := rv.Request.UserInfo.Extra["secret-sauce"]
	if ok {
		if len(sauce) > 0 {
			for _, sauce := range sauce {
				if sauce == SecretSauce {
					return true
				}
			}
		}
	}
	return false
}

func getIP(r *http.Request) string {
	// 1. Try X-Forwarded-For (can be a comma-separated list)
	clientIP := r.Header.Get("X-Forwarded-For")

	// 2. Fallback to X-Real-IP
	if clientIP == "" {
		clientIP = r.Header.Get("X-Real-IP")
	}

	// 3. Last resort: The direct connection IP
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	return clientIP
}

func parseParams(params url.Values) (command []string, needsRecording bool, container string) {
	// first fetch the command parameters from the url params to check what commands were passed
	// initially to the container
	var ttyRequested, stdinRequested bool
	for key, value := range params {
		if key == "command" {
			command = value
		}
		// a tty session carries interactive keystrokes that must be audited
		if key == "tty" && len(value) > 0 && value[0] == "true" {
			ttyRequested = true
		}
		// stdin (kubectl exec -i) can drive an interactive interpreter such as
		// sh/bash/python without a tty. Without recording it, the entire session
		// would only be logged as its initial command, leaving an unaudited shell.
		if key == "stdin" && len(value) > 0 && value[0] == "true" {
			stdinRequested = true
		}
		// check for container param
		if key == "container" && len(value) > 0 {
			container = value[0]
		}
	}
	return command, ttyRequested || stdinRequested, container
}

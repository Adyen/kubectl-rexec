package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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

type protocolType string

const (
	protocolWebSocket protocolType = "websocket"
	protocolSPDY      protocolType = "spdy"
)

const (
	ctxSessionIDKey = "sessionID"
	ctxProtocolKey  = "protocol"
)

func Server() {
	// creating a mux router
	r := mux.NewRouter()

	// handling rexec request to handler
	r.HandleFunc("/apis/audit.adyen.internal/v1beta1/namespaces/{namespace}/pods/{pod}/exec", rexecHandler)
	// returning some dummy json making kubeapiserver happier
	r.HandleFunc("/apis/audit.adyen.internal/v1beta1", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(httpSpec))
	})
	// handle native pod exec through a validating webhook
	r.HandleFunc("/validate-exec", execHandler)

	// start tls listener
	http.ListenAndServeTLS(":8443", "/etc/pki/rexec/tls.crt", "/etc/pki/rexec/tls.key", r)
}

// rexecHandler is responsible for rewrite the request to an exec request
// and proxy it back to k8s api
func rexecHandler(w http.ResponseWriter, r *http.Request) {
	// parsing for vars
	pathParams := mux.Vars(r)
	namespace := pathParams["namespace"]
	pod := pathParams["pod"]
	user := r.Header.Get("X-Remote-User")

	// if any of the minimal parameters are missing we should bail
	if user == "" || namespace == "" || pod == "" {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(httpForbidden))
		return
	}
	r.Header.Add("Kubectl-Command", "kubectl exec")

	// adding the service account token we are using for impersonating
	r.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	// add user to impersonation header
	r.Header.Add("Impersonate-User", user)

	// adding all passed groups as impersonation groups
	groups := r.Header.Values("X-Remote-Group")
	for _, group := range groups {
		r.Header.Add("Impersonate-Group", group)
	}

	// for the webhook service part we need to signal somehow
	// that we are allowed to do execs, coming through this endpoint
	// so we pass a custom shared key through the `Impersonate-Extra-Secret-Sauce`
	// header which will end up in `admissionReview.Request.UserInfo.Extra`
	r.Header.Add("Impersonate-Extra-Secret-Sauce", SecretSauce)

	// template old and new url paths and replace them in the url
	newPath := fmt.Sprintf("api/v1/namespaces/%s/pods/%s/exec", namespace, pod)
	oldPath := fmt.Sprintf("apis/audit.adyen.internal/v1beta1/namespaces/%s/pods/%s/exec", namespace, pod)
	r.URL.Path = strings.ReplaceAll(r.URL.Path, oldPath, newPath)
	r.URL.RawPath = strings.ReplaceAll(r.URL.RawPath, oldPath, newPath)
	r.Host = "kubernetes.default.svc.cluster.local:443"

	params, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(httpInternalError))
		return
	}

	// first fetch the command parameters from the url params to check what commands were passed
	// initially to the container
	var initialCommand []string
	needsRecording := false
	for key, value := range params {
		if key == "command" {
			initialCommand = append(initialCommand, value...)
		}
		// we also check whether tty was requested, if so we will need to record the session
		if key == "tty" {
			needsRecording = true
		}
	}

	if !needsRecording {
		// if we dont need any recording, we just pass the request back to the kube apiserver
		url, _ := url.Parse("https://kubernetes.default.svc.cluster.local:443")
		proxy := httputil.NewSingleHostReverseProxy(url)

		proxy.Transport = &http.Transport{
			DisableKeepAlives:  true,
			DisableCompression: true,
			TLSClientConfig: &tls.Config{
				RootCAs: CAPool,
			},
		}

		// Log initial command as an audit event
		// as oneoff, since we dont do tty so there
		// wont be a recording and a session id
		logCommand(strings.Join(initialCommand, " "), user, "oneoff")

		proxy.FlushInterval = -1

		proxy.ServeHTTP(w, r)
	} else {
		// in the case of recording we will pass the request through a tcp proxy to make it easier
		// to actually monitor what is being typed in to the shell

		// we begin to generate a uuid for the session and we set it as the id of a context
		// we will use this id to keep track what use the session belongs to
		ctxid := uuid.New().String()
		ctx := context.WithValue(r.Context(), ctxSessionIDKey, ctxid)
		ctx = context.WithValue(ctx, ctxProtocolKey, detectProtocol(r))

		// we save the session id into a map with the user's identity
		mapSync.Lock()
		userMap[ctxid] = user
		mapSync.Unlock()

		// we set the previously generated context to the request
		r.WithContext(ctx)

		// Log initial command as an audit event
		// with session id
		logCommand(strings.Join(initialCommand, " "), user, ctxid)

		// we start up a tcp forwarder for the session
		go tcpForwarder(ctx)

		// we need to wait a bit until the listener is actually there
		// probably there are 10 more sophisticated ways to do this
		// but it is not important now
		err = waitForListener(ctxid)
		if err != nil {
			SysLogger.Error().Err(err).Msg("waiting for listener")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(httpInternalError))
			return
		}

		// url does not really matter we are going through the socket anyway
		url, _ := url.Parse("http://localhost:8080")
		proxy := httputil.NewSingleHostReverseProxy(url)

		proxy.Transport = &http.Transport{
			DisableKeepAlives:  true,
			DisableCompression: true,
			// we are forcing the reverse proxy to go through our socket
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", fmt.Sprintf("/%s", ctxid))
			},
		}

		proxy.FlushInterval = -1

		proxy.ServeHTTP(w, r)
	}
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
	w.Write(respBytes)
}

// waitForListener is checking whether the tcp forwarder
// is ready or not, if it is not there after 5 secs
// it bails
func waitForListener(listener string) error {
	// again, super lazy but it is fine for now
	for i := 0; i < 5; i++ {
		if proxyMap[listener] {
			SysLogger.Debug().Msgf("socket became ready on try %d", i)
			return nil
		}
		SysLogger.Debug().Msgf("waiting for socket on try %d", i)
		time.Sleep(1 * time.Second)
	}
	return errors.New("socket was not ready in time")
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

func detectProtocol(r *http.Request) protocolType {
	upgrade := strings.ToLower(r.Header.Get("Upgrade"))
	if strings.Contains(upgrade, "spdy") {
		return protocolSPDY
	}
	return protocolWebSocket
}

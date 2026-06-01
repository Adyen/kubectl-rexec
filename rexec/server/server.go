package server

import (
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

	// we check if the initially loaded jwt is still valid, if not we refresh it
	err := ensureValidToken()
	if err != nil {
		SysLogger.Error().Err(err).Msg("failed to check the service account token")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(httpInternalError))
		return
	}
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
	r.Host = apiServerHost + ":443"

	params, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(httpInternalError))
		return
	}

	initialCommand, needsRecording, container := parseParams(params)
	clientIP := getIP(r)

	apiServerURL, _ := url.Parse("https://" + apiServerDial)
	proxy := httputil.NewSingleHostReverseProxy(apiServerURL)
	proxy.FlushInterval = -1
	cmd := strings.Join(initialCommand, " ")

	if !needsRecording {
		proxy.Transport = apiServerTransport()
		logCommand(cmd, user, "oneoff", namespace, pod, container, clientIP)
		proxy.ServeHTTP(w, r)
		return
	}

	// tty exec audit keystrokes on tls conn see tcplogger
	ctxid := uuid.New().String()
	registerSession(ctxid, user, namespace, pod, container, clientIP)
	defer endSession(ctxid)

	logCommand(cmd, user, ctxid, namespace, pod, container, clientIP)
	proxy.Transport = auditedAPIServerTransport(ctxid)
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

func parseParams(params url.Values) (command []string, ttyRequested bool, container string) {
	// first fetch the command parameters from the url params to check what commands were passed
	// initially to the container
	for key, value := range params {
		if key == "command" {
			command = value
		}
		// we also check whether tty was requested, if so we will need to record the session
		if key == "tty" {
			ttyRequested = true
		}
		// check for container param
		if key == "container" && len(value) > 0 {
			container = value[0]
		}
	}
	return command, ttyRequested, container
}

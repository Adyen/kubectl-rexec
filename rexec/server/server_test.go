package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gorilla/mux"
	admissionv1 "k8s.io/api/admission/v1"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// --- helpers ---

func postExecHandler(t *testing.T, ar admissionv1.AdmissionReview, contentType string) (rr *httptest.ResponseRecorder, got admissionv1.AdmissionReview) {
	t.Helper()

	body, err := json.Marshal(ar)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/validate-exec", bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rr = httptest.NewRecorder()

	execHandler(rr, req)

	if rr.Code == http.StatusOK {
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal response: %v\nbody: %s", err, rr.Body.String())
		}
	}
	return rr, got
}

// makeAdmissionReview builds a minimal AdmissionReview with kind, username, etc
func makeAdmissionReview(kind, username string, extra map[string][]string) admissionv1.AdmissionReview {
	ex := map[string]authv1.ExtraValue{}
	for k, v := range extra {
		ex[k] = authv1.ExtraValue(v)
	}
	return admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:  "uid-1",
			Kind: metav1.GroupVersionKind{Kind: kind},
			UserInfo: authv1.UserInfo{
				Username: username,
				Extra:    ex,
			},
		},
	}
}

// --- execHandler tests ---

func TestExecHandlerUnsupportedContentType(t *testing.T) {
	rr, _ := postExecHandler(t, admissionv1.AdmissionReview{}, "text/plain")
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusUnsupportedMediaType)
	}
}

func TestExecHandlerBadJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/validate-exec", bytes.NewReader([]byte("{bad-json")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	execHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestExecHandlerAllowsNonExecKinds(t *testing.T) {
	ar := makeAdmissionReview("Not-PodExecOptions", "", nil)

	rr, parsed := postExecHandler(t, ar, "application/json")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if parsed.Response == nil || !parsed.Response.Allowed {
		t.Fatalf("expected Allowed=true for non-PodExecOptions, got: %+v", parsed.Response)
	}
}

func TestExecHandlerBypassedUser(t *testing.T) {
	oldBypass := ByPassedUsers
	t.Cleanup(func() { ByPassedUsers = oldBypass })

	ByPassedUsers = []string{"lauren"}

	ar := makeAdmissionReview("PodExecOptions", "lauren", nil)

	rr, parsed := postExecHandler(t, ar, "application/json")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if parsed.Response == nil || !parsed.Response.Allowed {
		t.Fatalf("expected Allowed=true via ByPassedUsers, got: %+v", parsed.Response)
	}
}

func TestExecHandlerSecretSauce(t *testing.T) {
	oldBypass := ByPassedUsers
	oldSauce := SecretSauce
	t.Cleanup(func() {
		ByPassedUsers = oldBypass
		SecretSauce = oldSauce
	})

	ByPassedUsers = nil
	SecretSauce = "the-right-sauce"

	ar := makeAdmissionReview("PodExecOptions", "lauren", map[string][]string{
		"secret-sauce": {"the-right-sauce"},
	})

	rr, parsed := postExecHandler(t, ar, "application/json")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if parsed.Response == nil || !parsed.Response.Allowed {
		t.Fatalf("expected Allowed=true via secret-sauce, got: %+v", parsed.Response)
	}
}

func TestExecHandlerExecDenied(t *testing.T) {
	oldBypass := ByPassedUsers
	oldSauce := SecretSauce
	t.Cleanup(func() {
		ByPassedUsers = oldBypass
		SecretSauce = oldSauce
	})

	ByPassedUsers = nil
	SecretSauce = "the-right-sauce"

	ar := makeAdmissionReview("PodExecOptions", "lauren", map[string][]string{
		"secret-sauce": {"the-wrong-sauce"},
	})

	rr, parsed := postExecHandler(t, ar, "application/json")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if parsed.Response == nil || parsed.Response.Allowed {
		t.Fatalf("expected Allowed=false, got: %+v", parsed.Response)
	}
	if parsed.Response.Result == nil || parsed.Response.Result.Message != "cannot use exec directly, use rexec plugin instead" {
		t.Fatalf("unexpected denial message: %+v", parsed.Response.Result)
	}
}

// --- canPass unit tests ---

func TestCanPassBypassUser(t *testing.T) {
	oldBypass := ByPassedUsers
	t.Cleanup(func() { ByPassedUsers = oldBypass })

	ByPassedUsers = []string{"lauren"}

	rv := makeAdmissionReview("", "lauren", nil)

	if !canPass(rv) {
		t.Fatal("expected canPass true for bypassed user")
	}
}

func TestCanPassSecretSauceMatch(t *testing.T) {
	oldBypass := ByPassedUsers
	oldSauce := SecretSauce
	t.Cleanup(func() {
		ByPassedUsers = oldBypass
		SecretSauce = oldSauce
	})

	ByPassedUsers = nil
	SecretSauce = "the-right-sauce"

	rv := makeAdmissionReview("", "", map[string][]string{
		"secret-sauce": {"the-right-sauce"}})
	if !canPass(rv) {
		t.Fatal("expected canPass true when secret-sauce matches")
	}
}

func TestCanPassNoMatch(t *testing.T) {
	oldBypass := ByPassedUsers
	oldSauce := SecretSauce
	t.Cleanup(func() {
		ByPassedUsers = oldBypass
		SecretSauce = oldSauce
	})

	ByPassedUsers = []string{"lauren"}
	SecretSauce = "the-right-sauce"

	rv := makeAdmissionReview("", "not-lauren", map[string][]string{
		"secret-sauce": {"the-wrong-sauce"}})
	if canPass(rv) {
		t.Fatal("expected canPass false when neither bypass nor sauce matches")
	}
}

// --- waitForListener unit test ---

func TestWaitForListenerReady(t *testing.T) {
	// Save/restore shared map
	oldProxyMap := proxyMap
	t.Cleanup(func() { proxyMap = oldProxyMap })

	// Use a fresh map for isolation
	proxyMap = map[string]bool{}

	// Mark ready before call so it should return quickly
	id := "session-123"
	proxyMap[id] = true

	start := time.Now()
	if err := waitForListener(id); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("waitForListener returned too slowly")
	}
}

// initCleanup saves all package-level state that Init modifies and restores it after the test.
func initCleanup(t *testing.T) {
	t.Helper()
	oldCAPath, oldTokenPath := caPath, tokenPath
	oldSauce := SecretSauce
	oldExitFn := exitFn
	t.Cleanup(func() {
		caPath, tokenPath = oldCAPath, oldTokenPath
		SecretSauce = oldSauce
		exitFn = oldExitFn
	})
}

func TestInitMissingCA(t *testing.T) {
	initCleanup(t)

	dir := t.TempDir()
	tf, err := os.CreateTemp(dir, "token")
	if err != nil {
		t.Fatal(err)
	}
	tf.WriteString("token-123")
	tf.Close()

	caPath = "/invalid/ca.crt"
	tokenPath = tf.Name()
	SecretSauce = ""

	exited := false
	exitFn = func(int) { exited = true }

	Init()

	if !exited {
		t.Fatal("expected fatal exit on missing CA cert, got none")
	}
}

func TestInitMissingToken(t *testing.T) {
	initCleanup(t)

	dir := t.TempDir()
	cf, err := os.CreateTemp(dir, "ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	cf.Close()

	caPath = cf.Name()
	tokenPath = "/invalid/token-123"
	SecretSauce = ""

	exited := false
	exitFn = func(int) { exited = true }

	Init()

	if !exited {
		t.Fatal("expected fatal exit on missing token, got none")
	}
}

func TestInitInvalidSecretSauce(t *testing.T) {
	initCleanup(t)

	dir := t.TempDir()
	cf, err := os.CreateTemp(dir, "ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	cf.Close()

	tf, err := os.CreateTemp(dir, "token")
	if err != nil {
		t.Fatal(err)
	}
	tf.WriteString("token-123")
	tf.Close()

	caPath = cf.Name()
	tokenPath = tf.Name()
	SecretSauce = "not-an-uuid"

	exited := false
	exitFn = func(int) { exited = true }

	Init()

	if !exited {
		t.Fatal("expected fatal exit on invalid SecretSauce, got none")
	}
}

// --- rexecHandler early validation test ---

func TestRexecHandlerMissingUser(t *testing.T) {
	// No X-Remote-User header
	req := httptest.NewRequest(http.MethodGet,
		"/apis/audit.adyen.internal/v1beta1/namespaces/ns/pods/pod/exec", nil)
	req = mux.SetURLVars(req, map[string]string{
		"namespace": "ns",
		"pod":       "pod",
	})

	rr := httptest.NewRecorder()

	rexecHandler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

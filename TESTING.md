# Testing Guide

Complete testing for `kubectl-rexec`.

## Exec contract tests

The E2E suite builds the plugin and server, installs them in a disposable Kind
cluster, and exercises the real aggregated API and validating webhook:

```bash
./scripts/e2e.sh
```

Docker, Kind, kubectl, and Go must be installed. Set
`REXEC_KEEP_CLUSTER=true` to retain the cluster for debugging. CI runs the
suite against Kubernetes 1.29 with
`TranslateStreamCloseWebsocketRequests=true` and Kubernetes 1.35.

The contract suite validates:

- stdout, stderr, command arguments, remote exit status, and execution errors
- stdin with and without a TTY, EOF, terminal resize, and merged TTY streams
- pod, namespace, deployment, service, manifest, default-container, and explicit-container targeting
- every command-local `exec` flag; adding a flag without contract coverage fails CI
- WebSocket interactive sessions, SPDY one-off sessions, and SPDY interactive rejection
- command, keystroke, lifecycle, user, pod, container, namespace, and client-IP audit fields
- user and group impersonation, upstream RBAC enforcement, and direct-exec denial
- missing and completed targets, plus pod-running timeout behavior

## Unit Tests

### Running Tests

```bash
go test ./rexec/server
go test ./plugin

go test -v -run TestParseFileSpec
```

## Plugin Tests (`plugin/`)

| Test | Description |
|------|-------------|
| `TestParseFileSpec` | Parses `pod:/path` and `ns/pod:/path` |
| `TestValidateLocalDestination` | Validates local path exists |
| `TestExtractTarSingleFile` | Extracts single file from tar |
| `TestExtractTarDirectory` | Extracts directory from tar |
| `TestExtractTarRenameDirectory` | Extracts directory with different name |
| `TestExtractTarLinkTypesSkipped` | Security: symlinks and hard links are skipped with warning |
| `TestExtractTarPathTraversal` | Security: path traversal attempts are blocked |
| `TestExtractTarValidDoubleDotFileName` | Valid filenames like `file..txt` are allowed |
| `TestExtractTarValidDoubleDotDirectoryName` | Valid directory names with `..` are allowed |
| `TestRunWithArgsValidation` | Rejects upload, pod-to-pod |
| `TestValidateCopySpecs` | Validates copy specs |
| `TestComputeSafeTarget` | Security: validates tar entry paths and targets |
| `TestProcessTarEntry` | Tests individual tar entry processing |
| `TestProcessTarEntryUnsupportedTypes` | Security: unsupported tar types are skipped with warning |

#### Server Tests (`rexec/server/`)

| Test | What It Tests |
|------|---------------|
| `TestExecHandlerUnsupportedContentType` | Rejects non-JSON requests |
| `TestExecHandlerBadJSON` | Handles malformed JSON |
| `TestExecHandlerAllowsNonExecKinds` | Allows non-PodExecOptions resources |
| `TestExecHandlerBypassedUser` | Bypassed users can exec |
| `TestExecHandlerSecretSauce` | Valid secret sauce allows exec |
| `TestExecHandlerExecDenied` | Invalid requests are denied |
| `TestCanPassBypassUser` | Bypass user logic |
| `TestCanPassSecretSauceMatch` | Secret sauce validation |
| `TestCanPassNoMatch` | Denial when no auth matches |
| `TestWaitForListenerReady` | Listener readiness check |
| `TestRexecHandlerMissingUser` | Missing user header returns 403 |

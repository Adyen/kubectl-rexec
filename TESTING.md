# Testing Guide

Complete testing for `kubectl-rexec`.

## Unit Tests

### Running Tests

```bash
cd plugin
go test -v

cd rexec/server
go test -v

go test -v -run TestParseFileSpec
```

#### Plugin Tests (`plugin/`)

| Test | What It Tests |
|------|---------------|
| `TestParseFileSpec` | File spec parsing: `/tmp/foo`, `pod:/tmp/foo`, `ns/pod:/tmp/foo` |
| `TestExtractTarSingleFile` | Tar extraction for single file |
| `TestExtractTarDirectory` | Tar extraction preserving directory structure |
| `TestExtractTarPathTraversal` | Security: rejects path traversal attacks |
| `TestExtractTarSymlinkSkipped` | Security: symlinks are skipped with warning |
| `TestExtractTarValidDoubleDotFilename` | Valid filenames like `file..txt` are allowed |
| `TestRunWithArgsValidation` | Argument validation (rejects upload, pod-to-pod, local-to-local) |

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

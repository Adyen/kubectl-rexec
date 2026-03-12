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

| Test | Description |
|------|-------------|
| `TestParseFileSpec` | Parses `pod:/path` and `ns/pod:/path` |
| `TestValidateLocalDestination` | Validates local path exists |
| `TestExtractTarSingleFile` | Extracts single file from tar |
| `TestExtractTarDirectory` | Extracts directory from tar |
| `TestExtractTarSymlinkSkipped` | Security: symlinks are skipped with warning |
| `TestExtractTarValidDoubleDotFilename` | Valid filenames like `file..txt` are allowed |
| `TestRunWithArgsValidation` | Rejects upload, pod-to-pod |
| `TestValidateCopySpecs` | Validates copy specs |

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

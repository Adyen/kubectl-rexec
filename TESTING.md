# Testing Guide

Complete testing for `kubectl-rexec`.

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

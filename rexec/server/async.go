package server

import "io"

type asyncAudit struct {
	ctxid string
	info  sessionInfo
	ascii []byte
}

// asyncAuditor merges keystrokes into command lines for audit logging.
func asyncAuditor() {
	SysLogger.Debug().Msg("starting asyncAuditor")
	for audit := range asyncAuditChan {
		storeOrFlush(audit)
	}
	SysLogger.Debug().Msg("channel closed, stopping asyncAuditor")
}

// storeOrFlush buffers keystrokes and flushes on enter or MaxStokesPerLine.
func storeOrFlush(audit asyncAudit) {
	for _, b := range audit.ascii {
		if b == 0 {
			continue
		}
		if AuditFullTraceLog {
			logKeystroke(b, audit.info.User, audit.ctxid, audit.info.NameSpace, audit.info.Pod, audit.info.Container, audit.info.ClientIP)
		}
		commandSync.Lock()
		switch b {
		case 8, 127: // backspace or delete
			buf := commandMap[audit.ctxid]
			if len(buf) > 0 {
				commandMap[audit.ctxid] = buf[:len(buf)-1]
			}
		case 3, 4: // ctrl+c or ctrl+d
			commandMap[audit.ctxid] = nil
		case 10, 13: // \n or \r
			flushCommandBufferLocked(audit.ctxid, audit.info)
		default:
			if b < 32 && b != 9 { // skip other control chars (keep tab)
				continue
			}
			if len(commandMap[audit.ctxid]) > MaxStokesPerLine {
				flushCommandBufferLocked(audit.ctxid, audit.info)
			}
			commandMap[audit.ctxid] = append(commandMap[audit.ctxid], b)
		}
		commandSync.Unlock()
	}
}

// flushCommandBufferLocked logs buffered keystrokes for a session and clears the buffer.
// Caller must hold commandSync when using flushCommandBufferLocked.
func flushCommandBufferLocked(ctxid string, info sessionInfo) {
	if cmd := commandMap[ctxid]; len(cmd) > 0 {
		logCommand(string(cmd), info.User, ctxid, info.NameSpace, info.Pod, info.Container, info.ClientIP)
		commandMap[ctxid] = nil
	}
}

type auditedStdin struct {
	r     io.Reader
	ctxid string
	info  sessionInfo
}

func newAuditedStdin(r io.Reader, ctxid string, info sessionInfo) io.Reader {
	if r == nil {
		return nil
	}
	return &auditedStdin{r: r, ctxid: ctxid, info: info}
}

func (a *auditedStdin) Read(p []byte) (int, error) {
	n, err := a.r.Read(p)
	if n > 0 {
		asyncAuditChan <- asyncAudit{ctxid: a.ctxid, info: a.info, ascii: append([]byte(nil), p[:n]...)}
	}
	return n, err
}

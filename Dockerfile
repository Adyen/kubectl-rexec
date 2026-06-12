FROM golang:1.26-bookworm@sha256:5f68ec6805843bd3981a951ffada82a26a0bd2631045c8f7dba483fa868f5ec5 AS builder

LABEL org.opencontainers.image.source=https://github.com/adyen/kubectl-rexec
LABEL org.opencontainers.image.description="Rexec proxy"
LABEL org.opencontainers.image.licenses=MIT

WORKDIR /workspace
COPY go.mod go.mod
COPY go.sum go.sum
COPY rexec/main.go main.go
COPY rexec/server rexec/server

RUN CGO_ENABLED=0 go build -a -o rexec-server .

FROM scratch
WORKDIR /
COPY --from=builder /workspace/rexec-server .

ENTRYPOINT ["/rexec-server"]

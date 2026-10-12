FROM golang:1.26-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c AS builder

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

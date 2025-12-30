FROM golang:1.25-bookworm@sha256:2c7c65601b020ee79db4c1a32ebee0bf3d6b298969ec683e24fcbea29305f10e AS builder

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

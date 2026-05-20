FROM golang:1.25-bookworm@sha256:1aafe6fe7d35f8f3cfd654ceb1bbd2cac8a0df4464afa2679e0ae60aba32efd8 AS builder

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

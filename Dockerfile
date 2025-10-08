FROM golang:1.25-bookworm@sha256:42d8e9dea06f23d0bfc908826455213ee7f3ed48c43e287a422064220c501be9 AS builder

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

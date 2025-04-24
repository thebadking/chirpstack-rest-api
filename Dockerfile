FROM golang:1.22-alpine AS builder
ENV CGO_ENABLED=0 \
    GO111MODULE=on

RUN apk update && \
    apk add --no-cache ca-certificates build-base

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN go build -o chirpstack-rest-api .


# ─── final stage ────────────────────────────────────────────────────────────────
FROM alpine:3.18.0

# install CA certs so TLS works
RUN apk add --no-cache ca-certificates

COPY --from=builder /app/chirpstack-rest-api /usr/bin/chirpstack-rest-api

USER nobody:nogroup

ENTRYPOINT ["/usr/bin/chirpstack-rest-api"]
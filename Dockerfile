FROM golang:1.18-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app
COPY . .

RUN go mod download
RUN go mod verify

RUN CGO_ENABLED=0 go build -tags=go_json -ldflags='-w -s' -o secretli

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs
COPY --from=builder /app/secretli /secretli

EXPOSE 8080
ENTRYPOINT ["/secretli"]

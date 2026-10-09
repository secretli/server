# The build stage runs on the native builder platform and cross-compiles for
# the target; running the Go compiler under QEMU emulation for arm64 makes
# the publish job many times slower for no benefit.

# mirror.gcr.io is Google's mirror of Docker Hub: the same images, without the
# limit Docker Hub puts on anonymous pulls from shared CI runners.
FROM --platform=$BUILDPLATFORM mirror.gcr.io/library/golang:1.27-alpine AS build
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X github.com/secretli/server/cmd.Version=${VERSION}" -o /secretli .

FROM gcr.io/distroless/static-debian12
COPY --from=build /secretli /secretli
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/secretli"]

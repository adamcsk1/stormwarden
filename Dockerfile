FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/stormwarden ./cmd/stormwarden

FROM alpine:3.23
RUN apk add --no-cache ca-certificates tzdata iputils traceroute && addgroup -S stormwarden && adduser -S -G stormwarden stormwarden && mkdir -p /data/exports && chown -R stormwarden:stormwarden /data
COPY --from=build /out/stormwarden /usr/local/bin/stormwarden
USER stormwarden
ENV DATA_PATH=/data/stormwarden.db EXPORT_DIR=/data/exports APP_LISTEN_ADDR=:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["stormwarden", "healthcheck"]
ENTRYPOINT ["stormwarden"]

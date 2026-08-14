FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/internet-analyzer ./cmd/internet-analyzer

FROM alpine:3.23
RUN apk add --no-cache ca-certificates tzdata && addgroup -S analyzer && adduser -S -G analyzer analyzer && mkdir -p /data/exports && chown -R analyzer:analyzer /data
COPY --from=build /out/internet-analyzer /usr/local/bin/internet-analyzer
USER analyzer
ENV DATA_PATH=/data/internet-analyzer.db EXPORT_DIR=/data/exports APP_LISTEN_ADDR=:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["internet-analyzer", "healthcheck"]
ENTRYPOINT ["internet-analyzer"]

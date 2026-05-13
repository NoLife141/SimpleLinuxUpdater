# Build stage
FROM golang:1.26.3-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o webserver .

# Runtime stage
FROM alpine:3.22
ENV GIN_MODE=release
RUN apk --no-cache add ca-certificates su-exec
RUN addgroup -S app && adduser -S -G app app && mkdir -p /app /data && chown -R app:app /app /data
WORKDIR /app
COPY --from=builder --chown=app:app /app/webserver .
COPY --from=builder --chown=app:app /app/templates ./templates
COPY --from=builder --chown=app:app /app/static ./static
COPY --chown=root:root docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["./webserver"]

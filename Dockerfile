# Build stage
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o webserver webserver.go

# Runtime stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates openssh-client
WORKDIR /root/
RUN mkdir -p /data
COPY --from=builder /app/webserver .
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static
VOLUME ["/data"]
EXPOSE 8080
CMD ["./webserver"]

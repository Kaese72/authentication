# syntax=docker/dockerfile:1
# Build
FROM --platform=linux/amd64 docker.io/golang:1.25-alpine AS builder
WORKDIR /workspace
COPY . .
RUN CGO_ENABLED=0 go build -o authentication-api

FROM alpine:latest
WORKDIR /root/
COPY --from=builder /workspace/authentication-api ./
EXPOSE 8080
CMD ["./authentication-api"]

# First stage: build the Go binary
FROM golang:1.26.1 AS builder
WORKDIR /app
COPY . .
RUN go mod tidy
RUN go build -o auth-system main.go

# Second stage: lightweight runtime
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/auth-system .
EXPOSE 8080
CMD ["./auth-system"]

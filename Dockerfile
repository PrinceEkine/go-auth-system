# First stage: build the Go binary
FROM golang:1.26.1 AS builder
WORKDIR /app

# Copy go.mod and go.sum first (better caching)
COPY go.mod go.sum ./
RUN go mod tidy

# Copy the rest of the source
COPY . .

# Build the binary
RUN go build -o auth-system main.go

# Second stage: lightweight runtime
FROM alpine:latest
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/auth-system .

EXPOSE 8080
CMD ["./auth-system"]

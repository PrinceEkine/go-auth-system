FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY . .
RUN go mod tidy
RUN go build -o auth-system main.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/auth-system .
EXPOSE 8080
CMD ["./auth-system"]

FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o authgate ./cmd/authgate

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /app

COPY --from=builder /app/authgate .
COPY --from=builder /app/migrations ./migrations
COPY --from=builder /app/templates ./templates

EXPOSE 8080

CMD ["./authgate"]
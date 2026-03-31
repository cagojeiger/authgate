FROM golang:1.25-alpine AS builder
ENV GOTOOLCHAIN=local

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /webapp .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /webapp /webapp

EXPOSE 9090
ENTRYPOINT ["/webapp"]

FROM golang:1.25-alpine AS builder
ENV GOTOOLCHAIN=local

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /authgate ./cmd/authgate/

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /authgate /authgate
COPY migrations/ /migrations/

EXPOSE 8080
ENTRYPOINT ["/authgate"]

FROM golang:1.22-alpine AS go-builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build -ldflags "-s -w -extldflags '-static'" -o ./main cmd/main.go

FROM alpine:latest

WORKDIR /app

RUN apk --no-cache add ca-certificates

COPY config/prod.yaml /app/config/prod.yaml

COPY --from=go-builder /app/main .

ENV CONFIG_PATH=./config/prod.yaml

CMD ["./main"]
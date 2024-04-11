FROM golang:1.22-alpine AS build

WORKDIR /build
COPY . .
RUN CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build -ldflags "-s -w -extldflags '-static'" -o ./app cmd/main.go
RUN apk add upx
RUN upx ./app

FROM scratch
COPY --from=build /build/app /app

ENTRYPOINT ["/app"]
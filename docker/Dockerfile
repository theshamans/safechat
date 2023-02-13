FROM golang:1.18 AS build

WORKDIR /app

COPY go.mod .
COPY encryption ./encryption
COPY server ./server

RUN go build -o /main ./server/main.go

FROM debian:bullseye-slim

COPY --from=build /main /main

RUN useradd -m nonroot
USER nonroot

EXPOSE 2345

ENTRYPOINT ["/main"]

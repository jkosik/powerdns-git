FROM golang:latest as builder
WORKDIR /root
COPY pdns-zoner.go .
RUN go get -d ./...
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo pdns-zoner.go #go ver <1.10

FROM alpine:latest  
RUN apk --no-cache add ca-certificates
RUN apk add curl
COPY --from=builder /root/pdns-zoner /usr/local/bin/pdns-zoner


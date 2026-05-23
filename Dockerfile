# 构建阶段
FROM golang:1.24-alpine AS builder
WORKDIR /app

ENV GO111MODULE=on
ENV GOPROXY=https://goproxy.cn,direct

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o dns-firewall ./main.go

# 运行阶段
FROM alpine:latest
WORKDIR /app

RUN apk add --no-cache tzdata ca-certificates && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone && \
    addgroup -g 1000 dnsgroup && \
    adduser -u 1000 -G dnsgroup -s /bin/sh -D dnsuser

COPY --from=builder /app/dns-firewall .

RUN chown -R dnsuser:dnsgroup /app
USER dnsuser

EXPOSE 8053/udp
EXPOSE 2112/tcp

CMD ["./dns-firewall", "-config", "/etc/dns-firewall/config.yaml"]
# 构建阶段 
FROM golang:1.24-alpine AS builder
WORKDIR /app

# 👉 【核心修改】配置中国大陆官方推荐的 Go 模块代理
ENV GO111MODULE=on
ENV GOPROXY=https://goproxy.cn,direct

# 优先缓存依赖
COPY go.mod go.sum ./
RUN go mod download

# 复制源码并编译
COPY . .
# 剔除符号表减小体积，关闭 CGO 提高可移植性
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o dns-firewall ./main.go

# 运行阶段
FROM alpine:latest
WORKDIR /app
# 安装时区数据
RUN apk add --no-cache tzdata && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone

COPY --from=builder /app/dns-firewall .

EXPOSE 8053/udp
EXPOSE 2112/tcp

CMD ["./dns-firewall"]
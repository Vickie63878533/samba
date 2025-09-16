# --- Build Stage ---
FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

# 复制源代码
COPY . .

# 构建 Go 应用
# -ldflags="-w -s" 用于减小二进制文件大小（去除调试信息）
# CGO_ENABLED=0 用于静态链接，确保在 Alpine 等最小镜像中没有 C 依赖问题
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/proxy-server ./main.go

# --- Runtime Stage ---
FROM alpine:latest

# 设置工作目录
WORKDIR /root/

# 从构建阶段复制编译好的二进制文件
COPY --from=builder /app/proxy-server .


# 暴露应用监听的端口
EXPOSE 7860

# ENV OPENAI_API_KEY="your_default_key_if_any" # 建议在运行时通过 -e 提供
ENV PORT="7860"

# 运行应用
CMD ["./proxy-server"]
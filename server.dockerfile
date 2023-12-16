# 使用 Rust 官方提供的 Docker 镜像作为基础镜像
FROM rust:latest as builder

# 设置工作目录
WORKDIR /build

# 复制 Rust 项目文件到容器中
COPY . .

# 对称加密的密钥，必须是32字节，默认可以不填 
ENV SECRET_KEY=0123456789abcdef0123456789abcdef

# 在构建阶段中编译 Rust 项目，生成可执行文件
RUN cargo build --bin http-proxy-server --release

# 创建一个新的镜像阶段，减小镜像大小并仅包含二进制文件
FROM debian:testing-slim

# 设置工作目录
WORKDIR /http2-server

# 从构建阶段的容器中复制二进制文件到最终镜像中
COPY --from=builder /build/target/release/http-proxy-server .

# 指定程序启动命令
CMD ["./http-proxy-server"]

# 代理服务端的端口
EXPOSE 1081
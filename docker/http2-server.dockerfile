FROM debian:testing-slim

# 设置工作目录
WORKDIR /http2-server

RUN mkdir conf

ENV HOME=/http2-server/conf

# 打包可执行文件
COPY ./target/release/http-proxy-server .

# 指定程序启动命令
CMD ["./http-proxy-server"]

# 代理服务器的端口
EXPOSE 1081
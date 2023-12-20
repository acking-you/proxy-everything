FROM debian:testing-slim

# 设置工作目录
WORKDIR /http2-client

RUN mkdir conf

VOLUME ["/http2-client/conf"]

ENV HOME=/http2-client/conf

# 打包可执行文件
COPY ./target/release/http-proxy-client .

# 指定程序启动命令
CMD ["./http-proxy-client"]

# 代理客户端的端口
EXPOSE 1080
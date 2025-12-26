FROM debian:testing-slim

ARG TARGETARCH

WORKDIR /http2-server

RUN mkdir conf

ENV HOME=/http2-server/conf

# Server port (default: 1081)
ENV SERVER_PORT=1081

# Transparent proxy target (optional, enables chain mode)
# ENV TURELY_PROXY_SERVER=

COPY ./linux-${TARGETARCH}/http-proxy-server .

CMD ["./http-proxy-server"]

EXPOSE 1081

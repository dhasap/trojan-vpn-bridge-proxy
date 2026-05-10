FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends openconnect ocproxy ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY start-howdy.sh /usr/local/bin/start-howdy.sh
RUN chmod +x /usr/local/bin/start-howdy.sh

EXPOSE 1080
ENTRYPOINT ["/usr/local/bin/start-howdy.sh"]

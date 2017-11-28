FROM debian:8
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      git-all \
      libdbus-1-dev \
      libsystemd-daemon-dev

RUN mkdir /packages && chown 777 /packages
COPY build_hsflowd /root/build_hsflowd
ENTRYPOINT ["/root/build_hsflowd"]

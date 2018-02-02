FROM opxhub/build:2.2
RUN apt-get update && apt-get install -y --no-install-recommends \
      libdbus-1-dev \
      libsystemd-daemon-dev \
      libopx-base-model-dev \
      libssl-dev
COPY build_hsflowd /root/build_hsflowd
ENTRYPOINT ["/root/build_hsflowd"]

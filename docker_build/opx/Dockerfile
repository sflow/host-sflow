FROM opxhub/build:2.2
RUN apt-get update
RUN git clone https://github.com/open-switch/opx-build
RUN apt-get install -y --no-install-recommends \
      libdbus-1-dev \
      libsystemd-daemon-dev \
      libopx-base-model-dev
RUN mkdir /packages && chown 777 /packages
COPY build_hsflowd /root/build_hsflowd
ENTRYPOINT ["/root/build_hsflowd"]

ARG ALPINE_VERSION=3.19

FROM golang:alpine${ALPINE_VERSION} as build
RUN apk --update add \
      libpcap-dev \
      build-base \
      linux-headers \
      gcc \
      git \
      openssl-dev \
      util-linux-dev \
 && git clone https://github.com/sflow/host-sflow.git \
 && cd host-sflow \
 && make all install FEATURES="DOCKER PCAP OVS TCP DROPMON CONTAINERD CONTAINERDGO K8S" PROCFS=/rootproc

FROM alpine:${ALPINE_VERSION} as complete
COPY --from=build /usr/sbin/hsflowd_containerd /usr/sbin/hsflowd_containerd
COPY --from=build /usr/sbin/hsflowd /usr/sbin/hsflowd
COPY --from=build /etc/hsflowd/ /etc/hsflowd/
COPY start.sh /
RUN apk add --no-cache tini dmidecode libpcap libuuid uuidgen \
 && ln -s /proc /rootproc

FROM scratch
COPY --from=complete / /
LABEL maintainer="InMon Corp. https://inmon.com"
LABEL description="Host sFlow agent"
LABEL url=https://hub.docker.com/r/sflow/host-sflow
LABEL license=https://inmon.com/technology/sflowlicense.txt
HEALTHCHECK CMD pidof hsflowd > /dev/null || exit 1
CMD ["/sbin/tini","--","/start.sh"]


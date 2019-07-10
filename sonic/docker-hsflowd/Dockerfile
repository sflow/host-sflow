FROM ubuntu:18.04 as builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      git-all \
      libssl-dev \
      libhiredis-dev

RUN git clone https://github.com/sflow/host-sflow && cd host-sflow && make FEATURES="SONIC" && make install

FROM ubuntu:18.04 as runner
RUN apt-get update && apt-get install -y --no-install-recommends \
      libhiredis0.13 \
      dumb-init
COPY --from=builder /usr/sbin/hsflowd /usr/sbin/hsflowd
COPY --from=builder /etc/hsflowd.conf /etc/hsflowd.conf
COPY --from=builder /etc/hsflowd/modules/* /etc/hsflowd/modules/
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["/usr/sbin/hsflowd", "-d"]


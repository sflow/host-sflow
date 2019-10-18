FROM nvidia/cuda:10.1-devel-centos7 as builder
RUN echo "UPDATE" && yum -y update
RUN echo "DEVTOOLS" && yum -y install \
    git \
    gcc \
    make
RUN echo "EXTRAS" && yum -y install \
    libpcap-devel \
    openssl-devel
RUN git clone https://github.com/sflow/host-sflow \
    && cd host-sflow \
    && make all install FEATURES="PCAP TCP DOCKER NVML"

FROM nvidia/cuda:10.1-runtime-centos7
RUN echo "UPDATE" && yum -y update
RUN echo "EXTRAS" && yum -y install \
    libpcap \
    openssl
COPY --from=builder /usr/sbin/hsflowd /usr/sbin/hsflowd
COPY --from=builder /etc/hsflowd.conf /etc/hsflowd.conf
COPY --from=builder /etc/hsflowd/modules/* /etc/hsflowd/modules/
CMD /usr/sbin/hsflowd -m `uuidgen` -d

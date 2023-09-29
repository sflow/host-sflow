FROM nvidia/cuda:11.7.1-devel-ubuntu20.04
ARG DEBIAN_FRONTEND=noninteractive
RUN echo "UPDATE" && apt-get update && apt-get install -y --no-install-recommends \
    git \
    gcc \
    make \
    golang-go
RUN echo "EXTRAS" && apt-get install -y --no-install-recommends \
    libpcap-dev \
    libnfnetlink-dev \
    libxml2-dev \
    libssl-dev \
    libdbus-1-dev \
    uuid-dev
RUN echo "CERTS" && apt-get install -y --reinstall ca-certificates
RUN mkdir /packages && chown 777 /packages
COPY build_hsflowd /root/build_hsflowd
ENTRYPOINT ["/root/build_hsflowd"]




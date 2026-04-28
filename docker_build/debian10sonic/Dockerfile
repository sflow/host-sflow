FROM debian:buster
ARG DEBIAN_FRONTEND=noninteractive

# Remove existing sources and point to the archive
RUN rm /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian buster main" > /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian-security buster/updates main" >> /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian buster-updates main" >> /etc/apt/sources.list

# Disable the 'check-valid-until' flag since archive release files are expired
RUN echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check-valid-until

RUN apt-get update && apt-get install -y --no-install-recommends \
      git-all \
      make \
      gcc \
      clang \
      libhiredis-dev
RUN mkdir /packages && chown 777 /packages
COPY build_hsflowd /root/build_hsflowd
ENTRYPOINT ["/root/build_hsflowd"]




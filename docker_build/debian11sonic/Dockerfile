FROM debian:bullseye
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update && apt-get install -y --no-install-recommends \
      git-all \
      make \
      gcc \
      clang \
      libhiredis-dev
RUN mkdir /packages && chown 777 /packages
COPY build_hsflowd /root/build_hsflowd
ENTRYPOINT ["/root/build_hsflowd"]




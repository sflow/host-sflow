FROM ubuntu:14.04
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      git-all \
      libdbus-1-dev
RUN mkdir /packages && chown 777 /packages
COPY build_hsflowd /root/build_hsflowd
ENTRYPOINT ["/root/build_hsflowd"]

FROM rockylinux:9
RUN echo "UPDATE" && dnf -y update
RUN echo "DEVTOOLS" && dnf -y install gcc
RUN echo "EXTRAS" && dnf -y --enablerepo=crb install \
      git \
      libpcap-devel \
      libvirt-devel \
      libnfnetlink-devel \
      libxml2-devel \
      dbus-devel \
      openssl-devel \
      rsync \
      rpm-build \
      libuuid-devel
RUN mkdir /packages && chown 777 /packages
COPY build_hsflowd /root/build_hsflowd
ENTRYPOINT ["/root/build_hsflowd"]

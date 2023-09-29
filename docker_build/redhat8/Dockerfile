FROM rockylinux/rockylinux:8.4
RUN echo "UPDATE" && yum -y update
RUN echo "DEVTOOLS" && yum -y groupinstall "Development Tools"
RUN echo "YUM-UTILS" && yum -y install "yum-utils"
RUN echo "EXTRAS" && yum -y install \
      git \
#      libpcap-devel \
      libvirt-devel \
#      libnfnetlink-devel \
      libxml2-devel \
      dbus-devel \
      openssl-devel \
      rsync \
      libuuid-devel
RUN mkdir /packages && chown 777 /packages
COPY build_hsflowd /root/build_hsflowd
ENTRYPOINT ["/root/build_hsflowd"]

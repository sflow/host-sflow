FROM centos:7
RUN sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/CentOS-*.repo \
  && sed -i s/^#.*baseurl=http/baseurl=http/g /etc/yum.repos.d/CentOS-*.repo \
  && sed -i s/^mirrorlist=http/#mirrorlist=http/g /etc/yum.repos.d/CentOS-*.repo 
RUN echo "UPDATE" && yum -y update
RUN echo "DEVTOOLS" && yum -y groupinstall "Development Tools"
RUN echo "EXTRAS" && yum -y install \
      git \
      clang \
      libpcap-devel \
      libvirt-devel \
      libnfnetlink-devel \
      libxml2-devel \
      rpm-build \
      dbus-devel \
      openssl-devel \
      libuuid-devel
RUN mkdir /packages && chown 777 /packages
COPY build_hsflowd /root/build_hsflowd
ENTRYPOINT ["/root/build_hsflowd"]

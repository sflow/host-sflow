FROM xenserver/xenserver-build-env
RUN echo "UPDATE" && yum -y update
# RUN echo "DEVTOOLS" && yum -y groupinstall "Development Tools"
RUN echo "EXTRAS" && yum -y install \
      dbus-devel \
      openssl-devel
RUN wget -q http://downloadns.citrix.com.edgesuite.net/11624/XenServer-7.0.0-binpkg.iso
RUN mkdir /packages && chown 777 /packages
COPY build_hsflowd /root/build_hsflowd
ENTRYPOINT ["/root/build_hsflowd"]

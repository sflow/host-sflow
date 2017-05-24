FROM ubuntu:14.04.5
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      git-all \
      libdbus-1-dev \
      libsystemd-daemon-dev

# insert libsystemd.so because OS10 has that library (and does not have libsystemd-daemon.so).
# we need to build mod_os10.so so that "ldd mod_os10.so" refers to "libsystemd.so.0". It's not
# enough to just link libsystemd.so to libsystemd-daemon.so here because the linker pulls the
# library name from inside the file, not from the filename.  This step should go away when
# OS10 moves to a newer base OS,  because libsystemd.so is present in newer Debian releases.
COPY libsystemd.so.0.3.1 /lib/x86_64-linux-gnu/
RUN ln -s /lib/x86_64-linux-gnu/libsystemd.so.0.3.1 /lib/x86_64-linux-gnu/libsystemd.so.0
RUN ln -s /lib/x86_64-linux-gnu/libsystemd.so.0.3.1 /usr/lib/x86_64-linux-gnu/libsystemd.so

RUN mkdir /packages && chown 777 /packages
COPY build_hsflowd /root/build_hsflowd
ENTRYPOINT ["/root/build_hsflowd"]

FROM apiemont/redhat9

# Installs gcc-2.96 from the Red Hat Linux 7 archives (even though we
# are in Red Hat Linux 9):
RUN rpm -e $(rpm -qa quota)  # clashing dependency (glibc-devel)
RUN rpm --ignorearch -i \
    http://archive.download.redhat.com/pub/redhat/linux/9/en/os/i386/RedHat/RPMS/glibc-kernheaders-2.4-8.10.i386.rpm \
    http://archive.download.redhat.com/pub/redhat/linux/9/en/os/i386/RedHat/RPMS/compat-gcc-7.3-2.96.118.i386.rpm \
    http://archive.download.redhat.com/pub/redhat/linux/9/en/os/i386/RedHat/RPMS/glibc-devel-2.3.2-11.9.i386.rpm \
    http://archive.download.redhat.com/pub/redhat/linux/9/en/os/i386/RedHat/RPMS/binutils-2.13.90.0.18-9.i386.rpm \
    # http://archive.download.redhat.com/pub/redhat/linux/7.0/en/os/i386/RedHat/RPMS/cpp-2.96-54.i386.rpm  \
    http://archive.download.redhat.com/pub/redhat/linux/9/en/os/i386/RedHat/RPMS/flex-2.5.4a-29.i386.rpm \
    http://archive.download.redhat.com/pub/redhat/linux/9/en/os/i386/RedHat/RPMS/vim-enhanced-6.1-29.i386.rpm \
    http://archive.download.redhat.com/pub/redhat/linux/9/en/os/i386/RedHat/RPMS/patch-2.5.4-16.i386.rpm

# # ubuntu-dependencies.txt is just a list of packages we want
# # installed. These are mostly prerequisites for compiling and
# # installing OpenSSL + Apache + mod_ssl.
# COPY ./ubuntu-requirements.txt /tmp/
# RUN apt-get update && xargs -a /tmp/ubuntu-requirements.txt apt-get install -y
# 
# # We need default sh to be bash for some configure scripts to work correctly
# # we could just run "bash ./configure ..." but the mod_ssl configure script
# # calls the apache one, so we need to change the default.
# # partial reference: https://serverfault.com/questions/84521/
# RUN ln -fs /bin/bash /bin/sh \
#     && dpkg-reconfigure -f noninteractive dash

# Make our compat-gcc-2.96 the main gcc
RUN cp /usr/bin/gcc296 /bin/gcc

# Wrap uname to trick the config scripts into thinking we're on i386:
RUN mv /bin/uname /bin/uname.real \
    && echo '#!/bin/bash' > /bin/uname \
    && echo '/bin/uname.real "$@" | sed "s/x86_64/i386/g" ' >> /bin/uname \
    && chmod a+x /bin/uname

# Download, install and compile OpenSSL 0.9.7
COPY djwj-openssl-patch /tmp/
RUN cd /tmp \
    && wget https://www.openssl.org/source/old/0.9.x/openssl-0.9.7.tar.gz \
    && tar --extract --gzip -f openssl-0.9.7.tar.gz \
    && cd openssl-0.9.7 \
    # && patch -p1 -i /tmp/djwj-openssl-patch \
    && sh ./config \
    && make
# but don't install it yet, mod_ssl will do that later.

# Download correct version of Apache
# COPY apache-modperl-patch /tmp/
RUN cd /tmp \
    && wget http://archive.apache.org/dist/httpd/binaries/linux/apache_1.3.26-i686-whatever-linux22.tar.gz \
    && tar --extract --gzip -f apache_1.3.26-i686-whatever-linux22.tar.gz

# But don't compile Apache yet, mod_ssl needs to add its own patches before we
# compile it.

# Pull in the pre-built SSL certificates from project repo.
COPY ssl-certificate /root/ssl-cert

# Download an appropriate version of mod_ssl. This one was chosen because:
#   - It is aimed at our specific version of Apache
#   - Expects OpenSSL and not its predecessor, SSLeay.
RUN cd /tmp \
    && wget www.modssl.org/source/OBSOLETE/mod_ssl-2.8.10-1.3.26.tar.gz \
    && tar --extract --gzip -f mod_ssl-2.8.10-1.3.26.tar.gz \
    && cd mod_ssl-2.8.10-1.3.26 \
    && bash ./configure --with-apache=../apache_1.3.26 --with-ssl=../openssl-0.9.7 --prefix=/usr/local/apache

# Once downloaded, we tell mod_ssl to configure and patch Apache as
# needed. We then compile and install our patched Apache, making sure
# to copy over our pre-built SSL certs into its conf directory.
RUN cd /tmp/apache_1.3.26 \
    && make \
    && cp -r /root/ssl-cert/* ./conf  \
    && make install

# Start it up
ENTRYPOINT /usr/local/apache/bin/httpd -DSSL -X \
           && echo "tail -f /usr/local/apache/logs/*_log" | /bin/bash

# Dodgy echo | bash above allows us to Ctrl+C out of the container
# (but running tail directly does not).

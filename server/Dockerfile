FROM ubuntu:rolling

# ubuntu-dependencies.txt is just a list of packages we want
# installed. These are mostly prerequisites for compiling and
# installing OpenSSL + Apache + mod_ssl.
COPY ./ubuntu-requirements.txt /tmp/
RUN apt-get update && xargs -a /tmp/ubuntu-requirements.txt apt-get install -y

# We need default sh to be bash for some configure scripts to work correctly
# we could just run "bash ./configure ..." but the mod_ssl configure script
# calls the apache one, so we need to change the default.
# partial reference: https://serverfault.com/questions/84521/
RUN ln -fs /bin/bash /bin/sh \
    && dpkg-reconfigure -f noninteractive dash

# Use old gcc
COPY gcc-old /root/gcc-old
RUN dpkg --install \
    /root/gcc-old/cpp-2.95_2.95.4-27_i386.deb \
    /root/gcc-old/gcc-2.95_2.95.4-27_i386.deb \
    /root/gcc-old/libstdc++2.10-dbg_2.95.4-27_i386.deb \
    /root/gcc-old/chill-2.95_2.95.4-27_i386.deb \
    /root/gcc-old/g++-2.95_2.95.4-27_i386.deb \
    /root/gcc-old/g77-2.95_2.95.4-27_i386.deb \
    /root/gcc-old/gobjc-2.95_2.95.4-27_i386.deb \
    /root/gcc-old/gpc-2.95_2.95.4-27_i386.deb \
    /root/gcc-old/libg++2.8.1.3-dev_2.95.4-27_i386.deb \
    /root/gcc-old/libg++2.8.1.3-glibc2.2_2.95.4-27_i386.deb \
    /root/gcc-old/libstdc++2.10-dev_2.95.4-27_i386.deb \
    /root/gcc-old/libstdc++2.10-glibc2.2_2.95.4-27_i386.deb

# Download, install and compile OpenSSL 0.9.7
RUN cd /tmp \
    && wget https://www.openssl.org/source/old/0.9.x/openssl-0.9.7.tar.gz \
    && tar --extract --auto-compress -f openssl-0.9.7.tar.gz \
    && cd openssl-0.9.7 \
    && /usr/bin/perl ./Configure linux-pentium \
    && make CC=gcc-2.95
# but don't install it yet, mod_ssl will do that later.

# Download and patch an appropriate version of Apache for our OpenSSL (version
# 1.3.27 since it's the first 64-bit release after OpenSSL 0.9.7 was released).
COPY apache-modperl-patch /tmp/
RUN cd /tmp \
    && wget https://archive.apache.org/dist/httpd/binaries/linux/apache_1.3.27-x86_64-whatever-linux22.tar.gz \
    && tar --extract --auto-compress -f apache_1.3.27-x86_64-whatever-linux22.tar.gz \
    && cd apache_1.3.27 \
    # patch thanks to http://www.gossamer-threads.com/lists/modperl/dev/98573
    && patch src/os/unix/os.h /tmp/apache-modperl-patch \
    # sed thanks to https://ubuntuforums.org/showthread.php?t=2162008
    && sed -i 's/getline/apache_getline/' src/support/htdigest.c \
    && sed -i 's/getline/apache_getline/' src/support/htpasswd.c \
    && sed -i 's/getline/apache_getline/' src/support/logresolve.c

# But don't compile Apache yet, mod_ssl needs to add its own patches before we
# compile it.

# Pull in the pre-built SSL certificates from project repo.
COPY ssl-certificate /root/ssl-cert

# Download an appropriate version of mod_ssl. This one was chosen because:
#   - It is aimed at our specific version of Apache
#   - Expects OpenSSL and not its predecessor, SSLeay.
RUN cd /tmp \
    && wget www.modssl.org/source/OBSOLETE/mod_ssl-2.8.14-1.3.27.tar.gz \
    && tar --extract --auto-compress -f mod_ssl-2.8.14-1.3.27.tar.gz \
    && cd mod_ssl-2.8.14-1.3.27 \
    && bash ./configure --with-apache=../apache_1.3.27 --with-ssl=../openssl-0.9.7 --prefix=/usr/local/apache

# Once downloaded, we tell mod_sll to configure and patch Apache as
# needed. We then compile and install our patched Apache, making sure
# to copy over our pre-built SSL certs into its conf directory.
RUN cd /tmp/apache_1.3.27 \
    && make \
    && cp -r /root/ssl-cert/* ./conf  \
    && make install

# Start it up
ENTRYPOINT /usr/local/apache/bin/apachectl startssl \
           && echo "tail -f /usr/local/apache/logs/*_log" | /bin/bash

# Dodgy echo | bash above allows us to Ctrl+C out of the container
# (but running tail directly does not).

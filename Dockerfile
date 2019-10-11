FROM ubuntu:rolling

COPY ubuntu-dependencies.txt /tmp/
RUN apt-get update && xargs -a /tmp/ubuntu-dependencies.txt apt-get install -y

RUN mkdir /project

# We need default sh to be bash for some configure scripts to work correctly
# we could just run "bash ./configure ..." but the mod_ssl configure script
# calls the apache one, so we need to change the default.
# partial reference: https://serverfault.com/questions/84521/
RUN ln -fs /bin/bash /bin/sh \
    && dpkg-reconfigure -f noninteractive dash

RUN cd /tmp \
    && wget https://www.openssl.org/source/old/0.9.x/openssl-0.9.7.tar.gz \
    && tar --extract --auto-compress -f openssl-0.9.7.tar.gz \
    && cd openssl-0.9.7 \
    && sh ./config \
    && make

# don't install openssl yet, let mod_ssl do that later

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

# don't make or apache yet, we do that as part of mod_ssl installation later
# e.g. mod_ssl patches the apache source

COPY ssl-certificate /root/ssl-cert

RUN cd /tmp \
    && wget www.modssl.org/source/OBSOLETE/mod_ssl-2.8.14-1.3.27.tar.gz \
    && tar --extract --auto-compress -f mod_ssl-2.8.14-1.3.27.tar.gz \
    && cd mod_ssl-2.8.14-1.3.27 \
    && bash ./configure --with-apache=../apache_1.3.27 --with-ssl=../openssl-0.9.7 --prefix=/usr/local/apache \
    && cd ../apache_1.3.27 \
    && make \
    # copy results from previous `make certificate` call
    && cp -r /root/ssl-cert/* ./conf  \
    && make install
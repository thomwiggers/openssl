FROM ubuntu:latest

RUN apt-get update -y
RUN apt-get install -y build-essential git libssl-dev unzip xsltproc wget bash

COPY . /opt/openssl

# Compile everything
## Build libcsidh
WORKDIR /opt
RUN git clone git://github.com/thomwiggers/constant-csidh-c-implementation.git --depth 1 csidh
WORKDIR /opt/csidh
RUN make -j7

RUN mkdir -p /opt/openssl/csidh/include/csidh
RUN mkdir -p /opt/openssl/csidh/lib
RUN rm /opt/openssl/csidh/lib/libcsidh.a
RUN cp /opt/csidh/libcsidh.a /opt/openssl/csidh/lib
RUN cp /opt/csidh/libcsidh.h /opt/openssl/csidh/include/csidh

WORKDIR /opt/openssl
RUN ./Configure no-shared enable-ssl-trace enable-ec_nistp_64_gcc_128 -lm linux-x86_64
RUN make -j7

EXPOSE 4433
ENTRYPOINT ["/opt/openssl/entrypoint.sh"]

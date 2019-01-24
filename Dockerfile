FROM ubuntu:latest

EXPOSE 8443/tcp

RUN apt-get update -y
RUN apt-get install -y build-essential git libssl-dev unzip xsltproc wget bash

COPY . /opt/openssl

# Compile everything
## Build OQS
WORKDIR /opt
RUN git clone git://github.com/open-quantum-safe/liboqs.git --branch nist-branch --depth=1
WORKDIR /opt/liboqs
RUN make -j7 && make install-noshared PREFIX=/opt/openssl/oqs

## Build openssl
WORKDIR /opt/openssl
RUN ./Configure no-shared enable-ssl-trace enable-ec_nistp_64_gcc_128 --debug -lm linux-x86_64
RUN make -j7

EXPOSE 4433
ENTRYPOINT ["/opt/openssl/entrypoint.sh"]

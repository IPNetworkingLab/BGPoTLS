FROM alpine:3.20 AS birdtls
RUN apk update && \
    apk upgrade --available && \
    apk add openssh libssh


FROM birdtls AS builder
RUN apk update && \
    apk upgrade --available && \
    apk add bison flex ncurses-dev \
            readline-dev linux-headers libssh-dev \
            autoconf gcc musl-dev git openssl \
            openssl-dev cmake make ninja g++

# Get and Build picotls
RUN git clone https://github.com/h2o/picotls.git /opt/picotls && \
    cd /opt/picotls && \
    git submodule init && \
    git submodule update && \
    mkdir build && \
    cd /opt/picotls/build && \
    cmake -DCMAKE_BUILD_TYPE=Release -GNinja .. && \
    ninja

# Build BGP over TLS
RUN mkdir /opt/bgpotls
COPY ./ /opt/bgpotls
RUN cd /opt/bgpotls && \
    autoreconf -sif && \
    ./configure \
        PICOTLS_HEADER=/opt/picotls/include/ \
        PICOTLS_LIB=/opt/picotls/build/ \
        --prefix=/usr \
        --sbindir=/usr/sbin \
        --sysconfdir=/etc/bird \
        --localstatedir=/var \
        --runstatedir=/run/ \
        --docdir=/usr/share/man && \
    make

FROM birdtls
COPY --from=builder /opt/bgpotls/bird /opt/bgpotls/birdc /opt/bgpotls/birdcl  /usr/sbin/
# create required files
RUN mkdir /etc/bird
# install tini init daemon
RUN apk add tini

ENTRYPOINT ["/sbin/tini", "/usr/sbin/bird", "--", "-f"]
CMD [ "-c", "/etc/bird/bird.conf" ] 

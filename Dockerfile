FROM debian:12-slim

RUN apt-get update && apt-get -y install make gcc-mingw-w64-x86-64

COPY . /srv

WORKDIR /srv

RUN make

FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential pkg-config libz-dev libjpeg-dev libpng-dev

COPY . /repo
WORKDIR /repo
RUN ./configure --prefix=/install
RUN make -j8
RUN make install

FROM ubuntu:22.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libjpeg-dev libpng-dev
COPY --from=builder /install /install

FROM rust

RUN dpkg --add-architecture armhf
RUN apt-get update && apt-get install -y libpam0g-dev libpam0g gcc-arm-linux-gnueabihf libpam0g-dev:armhf libpam0g:armhf

RUN rustup target add armv7-unknown-linux-gnueabihf

RUN cargo install just

COPY conf/config /usr/local/cargo/config

WORKDIR /usr/src/code
VOLUME [ "/usr/src/code" ]

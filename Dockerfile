FROM rust

RUN apt-get update && apt-get install -y libpam0g-dev libpam0g

WORKDIR /usr/src/code

RUN cargo install just

VOLUME [ "/usr/src/code" ]

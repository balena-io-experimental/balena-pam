
all:
    cargo build

install:
    @cargo build
    cp conf/jwt-auth /etc/pam.d/
    mkdir -p /lib/security
    cp target/debug/libpam_jwt.so /lib/security/pam_jwt.so

test:
    @just install
    mkdir -p /mnt/boot
    cp conf/config.json /mnt/boot/config.json
    gcc -o target/pam_test test.c -lpam -lpam_misc

build-test:
    docker run --rm -it -v ${PWD}:/usr/src/code rust-dev bash -c "just test && target/pam_test root"
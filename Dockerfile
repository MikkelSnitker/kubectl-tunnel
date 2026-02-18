FROM rust:latest as builder

WORKDIR /app

RUN rustup target add x86_64-unknown-linux-musl \
 && apt-get update \
 && apt-get install -y --no-install-recommends musl-tools pkg-config \
 && rm -rf /var/lib/apt/lists/*

# Cache dependencies
COPY Cargo.toml Cargo.lock ./

COPY .cargo ./
COPY src ./src
RUN cargo build --release --bin server --target x86_64-unknown-linux-musl




FROM alpine:latest

WORKDIR /scripts
RUN apk update && apk add iptables

COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/server /scripts/
#RUN apk update && apk add socat iptables
COPY init.sh /scripts/

CMD [ "/scripts/init.sh" ]
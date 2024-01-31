FROM rust:1.68 AS builder

WORKDIR /root
COPY . .

RUN mkdir -p /root/.cargo/ && \
    echo '[source.crates-io]' > .cargo/config && \
    echo 'replace-with = "rsproxy-sparse"' >> .cargo/config && \
    echo '[source.rsproxy]' >> .cargo/config && \
    echo 'registry = "https://rsproxy.cn/crates.io-index"' >> .cargo/config && \
    echo '[source.rsproxy-sparse]' >> .cargo/config && \
    echo 'registry = "sparse+https://rsproxy.cn/index/"' >> .cargo/config && \
    echo '[registries.rsproxy]' >> .cargo/config && \
    echo 'index = "https://rsproxy.cn/crates.io-index"' >> .cargo/config && \
    echo '[net]' >> .cargo/config && \
    echo 'git-fetch-with-cli = true' >> .cargo/config

RUN cargo build -r --bin arkime-rust

FROM alpine:3.18

WORKDIR /root
    
COPY --from=builder /root/target/release/arkime-rust .

CMD ["/root/arkime-rust"]
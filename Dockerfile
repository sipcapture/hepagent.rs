FROM rust:1.40 as builder
WORKDIR /usr/src/hepagent
COPY . .
RUN apt update && apt install -y luajit-5.1 libpcap-dev \
 && RUSTFLAGS="-C target-feature=+crt-static" \
 && cargo build --release

FROM debian:buster-slim
RUN apt-get update && apt-get install -y luajit-5.1 libpcap-dev && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/hepagent/target/release/hepagent /usr/local/hepagent/hepagent
COPY --from=builder /usr/src/hepagent/scripts /usr/local/hepagent/scripts
RUN ln -s /usr/local/hepagent/hepagent /usr/local/bin/hepagent
WORKDIR /usr/local/hepagent
CMD ["hepagent"]

run:
    - cargo build
    - sudo RUST_LOG=info ./target/debug/chaos-net \
        --container chaos-test \
        --iface eth0 \
        --rule "Outbound 10.88.0.1:8080 delay=100 jitter=30 loss=50" \
        --rule "Inbound 10.88.0.1:8080 delay=100 jitter=30 loss=50"
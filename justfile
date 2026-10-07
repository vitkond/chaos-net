run:
    - cargo build
    - sudo RUST_LOG=info ./target/debug/chaos-net \
        --container chaos-test \
        --rule 10.88.0.1:8080=5000 \
        --rule 10.88.0.1:8081=2000
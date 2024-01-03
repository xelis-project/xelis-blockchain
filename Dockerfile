# syntax=docker/dockerfile-upstream:master-labs

FROM rust:1.74-bookworm as builder

ARG app
ARG commit-hash

ENV BUILD_DIR /tmp/xelis-build
ENV XELIS_COMMIT_HASH ${commit-hash}

RUN mkdir -p $BUILD_DIR
WORKDIR $BUILD_DIR

COPY Cargo.toml Cargo.lock ./
COPY --parents xelis_common/src xelis_common/Cargo.toml xelis_common/build.rs ./
COPY --parents xelis_daemon/src xelis_daemon/Cargo.toml ./
COPY --parents xelis_miner/src xelis_miner/Cargo.toml ./
COPY --parents xelis_wallet/src xelis_wallet/Cargo.toml ./

WORKDIR ${BUILD_DIR}/$app

RUN cargo build --release

# ---

FROM gcr.io/distroless/cc-debian12

ARG app

ENV APP_DIR /var/run/xelis
ENV DATA_DIR $APP_DIR/data
ENV BINARY $APP_DIR/xelis

LABEL org.opencontainers.image.authors="Slixe <slixeprivate@gmail.com>"

COPY --from=builder /tmp/xelis-build/target/release/$app $BINARY

WORKDIR $DATA_DIR

ENTRYPOINT ["/var/run/xelis/xelis"]

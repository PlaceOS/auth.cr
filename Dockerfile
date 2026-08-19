ARG CRYSTAL_VERSION=latest

FROM placeos/crystal:$CRYSTAL_VERSION AS build
WORKDIR /app

# Set the commit via a build arg
ARG PLACE_COMMIT="DEV"
# Set the platform version via a build arg
ARG PLACE_VERSION="DEV"

# Create a non-privileged user, defaults are appuser:10001
ARG IMAGE_UID="10001"
ENV UID=$IMAGE_UID
ENV USER=appuser

# See https://stackoverflow.com/a/55757473/12429735
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"

# Install package updates since image release
RUN apk update && apk --no-cache --quiet upgrade

RUN update-ca-certificates

# Install shards for caching
COPY shard.yml shard.yml
COPY shard.override.yml shard.override.yml
COPY shard.lock shard.lock

RUN shards install --production --ignore-crystal-version --skip-postinstall --skip-executables

# Add src
COPY ./src /app/src

# Build application
# --debug + --frame-pointers + the link flags below are required so the binary
# ships DWARF info and an unwindable stack, i.e. runtime errors report backtraces
RUN UNAME_AT_COMPILE_TIME=true \
    PLACE_COMMIT=$PLACE_COMMIT \
    PLACE_VERSION=$PLACE_VERSION \
    shards build \
      --production \
      --error-trace \
      --no-color \
      --static \
      --debug \
      --frame-pointers=always \
      --link-flags "-no-pie -Wl,-no-pie -Wl,--eh-frame-hdr -Wl,--build-id -rdynamic -Wl,--export-dynamic -lunwind -llzma"

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

# Extract binary dependencies
# (a fully static, non-PIE binary has none -- deps must still exist for the COPY below)
RUN mkdir -p deps
RUN for binary in /app/bin/*; do \
        file "$binary" | grep -q "dynamically linked" || continue; \
        ldd "$binary" | \
        tr -s '[:blank:]' '\n' | \
        grep '^/' | \
        xargs -I % sh -c 'mkdir -p $(dirname deps%); cp % deps%;'; \
    done

# Generate OpenAPI docs while we still have source code access
RUN ./bin/placeos-auth --docs > openapi.yml

RUN git config --system http.sslCAInfo /etc/ssl/certs/ca-certificates.crt

# Build a minimal docker image
FROM scratch
WORKDIR /
ENV PATH=$PATH:/

# Copy the user information over
COPY --from=build etc/passwd /etc/passwd
COPY --from=build /etc/group /etc/group

# These are required for communicating with external services
COPY --from=build /etc/hosts /etc/hosts

# These provide certificate chain validation where communicating with external services over TLS
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# This is required for Timezone support
COPY --from=build /usr/share/zoneinfo/ /usr/share/zoneinfo/

# This is your application
COPY --from=build /app/deps /
COPY --from=build /app/bin /

# Copy the docs into the container, you can serve this file in your app
COPY --from=build /app/openapi.yml /openapi.yml

# Use an unprivileged user.
USER appuser:appuser

# Spider-gazelle has a built in helper for health checks
HEALTHCHECK CMD ["/placeos-auth", "-c", "http://127.0.0.1:8080/auth/healthz"]

# Run the app binding on port 8080
EXPOSE 8080
ENTRYPOINT ["/placeos-auth"]
CMD ["/placeos-auth", "-b", "0.0.0.0", "-p", "8080"]

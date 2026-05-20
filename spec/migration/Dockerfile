FROM placeos/crystal:latest

WORKDIR /app

COPY . /app

# Pulls the latest placeos-models master and applies every migration —
# including the `oauth_tokens` table the auth.cr token store needs.
# Override at build time with `--build-arg PLACEOS_MODELS_REF=<branch>`
# if you need to test against an in-flight model branch.
ARG PLACEOS_MODELS_REF=master
RUN git clone --branch "${PLACEOS_MODELS_REF}" https://github.com/PlaceOS/models
RUN mv ./models/migration/db ./db

ENV PATH=/app/bin:$PATH

RUN shards build

ENTRYPOINT [ "/app/run.sh" ]

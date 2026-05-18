FROM placeos/crystal:latest

WORKDIR /app

COPY . /app

# auth.cr pins models to the `auth-replacement` branch while migrations
# are landing for authly's token store and OIDC request tables.
RUN git clone --branch auth-replacement https://github.com/PlaceOS/models
RUN mv ./models/migration/db ./db

ENV PATH=/app/bin:$PATH

RUN shards build

ENTRYPOINT [ "/app/run.sh" ]

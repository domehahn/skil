FROM golang:1.24-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
COPY pkg/ pkg/
COPY schemas/ schemas/
COPY compat/asps/ compat/asps/
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/skil ./cmd/skil

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

RUN apt-get update \
    && apt-get install --no-install-recommends -y bubblewrap ca-certificates git yara \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system skil \
    && useradd --system --gid skil --create-home --home-dir /home/skil skil

COPY --from=build --chown=root:root /out/skil /usr/local/bin/skil
USER skil
WORKDIR /scan

ENTRYPOINT ["skil"]

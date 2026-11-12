FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev

WORKDIR /src
RUN apk add --no-cache --upgrade ca-certificates python3
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -mod=readonly -trimpath -buildvcs=false \
    -ldflags="-s -w -X main.version=$VERSION" \
    -o /out/switchboard ./cmd/switchboard
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -mod=readonly -trimpath -buildvcs=false \
    -ldflags="-s -w -X main.version=$VERSION" \
    -o /out/switchboard-module-log-watcher ./modules/log_watcher
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -mod=readonly -trimpath -buildvcs=false \
    -ldflags="-s -w -X main.version=$VERSION" \
    -o /out/switchboard-module-unifi ./modules/unifi
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH CGO_ENABLED=0 PYTHONPATH=/src/scripts \
    python3 -c "import os; from pathlib import Path; from release_notices import collect; notices, dependencies = collect(Path('/src'), os.environ, package=['./cmd/switchboard', './modules/log_watcher', './modules/unifi']); Path('/out/THIRD_PARTY_NOTICES.txt').write_bytes(notices); Path('/out/DEPENDENCIES.json').write_bytes(dependencies)"
RUN mkdir -p /out/rootfs/etc/switchboard/capabilities /out/rootfs/licenses/switchboard

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/switchboard /usr/local/bin/switchboard
COPY --from=build /out/switchboard-module-log-watcher /usr/local/libexec/switchboard/switchboard-module-log-watcher
COPY --from=build /out/switchboard-module-unifi /usr/local/libexec/switchboard/switchboard-module-unifi
COPY --from=build /out/rootfs/etc/switchboard /etc/switchboard
COPY --from=build /src/LICENSE /out/THIRD_PARTY_NOTICES.txt /out/DEPENDENCIES.json /licenses/switchboard/
USER 65532:65532
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/switchboard"]
CMD ["-config", "/etc/switchboard/switchboard.json"]

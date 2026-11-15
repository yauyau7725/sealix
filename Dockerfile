
FROM --platform=linux/amd64 golang:1.24.13-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac AS build

WORKDIR /src/app

COPY app/go.mod ./
COPY app/cmd ./cmd
COPY app/internal ./internal

ARG VERSION=dev 

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -buildvcs=false \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /sealix ./cmd/sealix

FROM scratch

ARG SOURCE_REPO=https://github.com/yauyau7725/sealix

LABEL org.opencontainers.image.source=${SOURCE_REPO}

COPY --from=build /sealix /sealix 

ENTRYPOINT [ "/sealix" ]

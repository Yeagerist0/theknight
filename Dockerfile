# Multi-stage: the runtime image carries the binary and nothing else.
FROM golang:1.26-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/theknight ./cmd/theknight

# Distroless: the CLI never shells out, so a shell and package manager in
# the runtime image would be attack surface with no use. Static base means
# no libc is needed for the CGO_ENABLED=0 binary above.
#
# Note this image carries no AWS credentials by design — pass them the
# normal way at run time, e.g.
#   docker run --rm -e AWS_PROFILE -v ~/.aws:/home/nonroot/.aws:ro theknight scan
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/theknight /theknight

USER nonroot:nonroot
ENTRYPOINT ["/theknight"]

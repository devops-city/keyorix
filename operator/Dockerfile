# Build stage. Build context is the operator/ module directory (a separate Go module
# from the main repo, so controller-runtime/client-go stay out of the server build).
FROM golang:1.27.3-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS builder
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/keyorix-operator ./cmd

# Runtime stage — distroless static, non-root. The operator reaches the Keyorix server
# over HTTPS (ca-certificates baked into the static base) and the Kubernetes API via the
# mounted ServiceAccount CA.
FROM gcr.io/distroless/static:nonroot@sha256:963fa6c544fe5ce420f1f54fb88b6fb01479f054c8056d0f74cc2c6000df5240
COPY --from=builder /out/keyorix-operator /usr/local/bin/keyorix-operator
USER 65532:65532
ENTRYPOINT ["keyorix-operator"]

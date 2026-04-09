FROM golang:1.25 AS builder

WORKDIR /src

COPY go.mod go.sum ./
COPY vendor ./vendor
COPY db ./db
COPY jenkins ./jenkins
COPY static ./static
COPY templates ./templates
COPY main.go notifier.go ./

RUN CGO_ENABLED=0 GOFLAGS=-mod=vendor go build -o /out/jenkis-history .

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /out/jenkis-history /app/jenkis-history

RUN mkdir -p /app/data

ENV PORT=3000
ENV DB_PATH=/app/data/data.db

EXPOSE 3000

CMD ["/app/jenkis-history"]

FROM golang:1.25 AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY db ./db
COPY jenkins ./jenkins
COPY templates ./templates
COPY main.go notifier.go ./

RUN CGO_ENABLED=0 go build -o /out/jenkins-public-build-history .

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /out/jenkins-public-build-history /app/jenkins-public-build-history
COPY --from=builder /src/templates /app/templates


RUN mkdir -p /app/data

ENV PORT=3000
ENV DB_PATH=/app/data/data.db

EXPOSE 3000

CMD ["/app/jenkins-public-build-history"]

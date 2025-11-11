# syntax=docker/dockerfile:1

FROM gcr.io/distroless/static:nonroot
LABEL org.opencontainers.image.title="tls-scan" \
      org.opencontainers.image.description="TLS/SSL verification and tracing tool" \
      org.opencontainers.image.license="GPL-3.0" \
      org.opencontainers.image.source="https://github.com/byteherders/tls-scan"

# Copy binary into container
COPY ./dist/tls-scan /usr/local/bin/tls-scan

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/tls-scan"]
CMD ["--help"]

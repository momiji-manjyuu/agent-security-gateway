# For reproducible production builds, replace the tag with a reviewed sha256 digest.
ARG BASE_IMAGE=python:3.12-slim-bookworm
FROM ${BASE_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp
WORKDIR /app
COPY contract.py worker.py /app/
RUN test -x /usr/bin/timeout && chmod -R a-w /app
USER 65532:65532
# An outer host watchdog also enforces a deadline and removes the container.
ENTRYPOINT ["/usr/bin/timeout", "--signal=KILL", "120s", "python", "-I", "/app/worker.py"]

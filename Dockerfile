FROM python:3.12-slim

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin isoforge
WORKDIR /app

COPY pyproject.toml README.md LICENSE SECURITY.md ./
COPY src ./src
COPY fixtures ./fixtures

RUN pip install --no-cache-dir . \
    && chown -R isoforge:isoforge /app

USER isoforge
EXPOSE 8583
ENTRYPOINT ["isoforge"]
CMD ["switch", "--port", "8583"]

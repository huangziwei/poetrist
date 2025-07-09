FROM python:3.13.0 AS builder

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

RUN python -m venv .venv
COPY pyproject.toml ./
COPY poetrist/ poetrist/
RUN python -m venv .venv \
    && .venv/bin/pip install -U pip \
    && .venv/bin/pip install . \
    && .venv/bin/pip install gunicorn
FROM python:3.13-slim
WORKDIR /app
ENV PORT=8080 PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

COPY --from=builder /app/.venv .venv/

EXPOSE 8080
CMD ["/app/.venv/bin/gunicorn", "-b", "0.0.0.0:8080", "poetrist.blog:app"]

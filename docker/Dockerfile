# syntax=docker/dockerfile:1
FROM python:3.12-slim

WORKDIR /app

RUN addgroup --system app && adduser --system --ingroup app app

COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/
RUN pip install --no-cache-dir -e .

USER app

ENTRYPOINT ["envsecure"]
CMD ["--help"]

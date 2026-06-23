FROM python:3.12-slim

LABEL maintainer="arkanzasfeziii"
LABEL description="Aegis — Offensive Network Attack Framework"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY aegis/ aegis/

ENTRYPOINT ["python", "-m", "aegis"]
CMD ["--help"]

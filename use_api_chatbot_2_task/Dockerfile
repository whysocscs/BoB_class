FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates build-essential gcc && \
    rm -rf /var/lib/apt/lists/*

ADD https://astral.sh/uv/install.sh /uv-installer.sh
RUN sh /uv-installer.sh && rm /uv-installer.sh

ENV PATH="/root/.local/bin/:$PATH"

WORKDIR /opt/bbot

COPY . .

RUN chmod +x /opt/bbot/start.sh

RUN uv pip install --python=/usr/local/bin/python -r requirements.txt

CMD ["bash", "start.sh"]

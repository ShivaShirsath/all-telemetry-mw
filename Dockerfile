FROM node:18-bookworm-slim
LABEL maintainer="Mahesh <mahesh@ilimi.in>"
RUN useradd -rm -d /home/sunbird -s /bin/bash -g root -G sudo -u 1001 sunbird
RUN apt-get update \
    && apt-get install -y --no-install-recommends unzip curl ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/*
USER sunbird
WORKDIR /home/sunbird/telemetry
COPY --chown=sunbird:root ./telemetry-service.zip /home/sunbird/telemetry/
RUN unzip -q /home/sunbird/telemetry/telemetry-service.zip
WORKDIR /home/sunbird/telemetry/telemetry/
EXPOSE 9001
CMD ["node", "app.js"]
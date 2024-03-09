FROM node:20-alpine AS builder
ENV NODE_ENV=production
ENV NODE_OPTIONS=--max_old_space_size=4096
# Uncomment the following line to enable agent logging
LABEL "network.forta.settings.agent-logs.enable"="true"
WORKDIR /app
COPY ./src ./src
COPY package*.json ./
COPY bot-config.json ./
COPY forta-bot-0.2.0.tgz ./
COPY forta-bot-cli-0.2.0.tgz ./
COPY LICENSE ./
RUN npm ci --production
CMD [ "npm", "run", "start:prod" ]

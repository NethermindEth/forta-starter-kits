FROM node:16-alpine
ENV NODE_ENV=production
# Uncomment the following line to enable agent logging
LABEL "network.forta.settings.agent-logs.enable"="true"
WORKDIR /app
COPY ./src ./src
COPY ./LICENSE ./
COPY package*.json ./
COPY bot-config.json ./
RUN npm ci --production
CMD [ "npm", "run", "start:prod" ]

FROM node:24-slim
WORKDIR /app
COPY package.json package-lock.json ./
# tsx runs the TypeScript sources directly, so the dev dependencies stay in.
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
# Set after the install: production makes the relay refuse to start without
# RELAY_STATIC_KEY instead of inventing a key no streamer has pinned.
ENV NODE_ENV=production PORT=8080
USER node
EXPOSE 8080
CMD ["node_modules/.bin/tsx", "src/index.ts"]

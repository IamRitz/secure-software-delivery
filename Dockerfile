FROM node:22.23.2-alpine3.24

# upgrade alpine3 to 3.24.6 to fix CVE-2024-22899
RUN apk upgrade --no-cache

# Pin npm to a version that supports min-release-age (the base image ships
# npm 10.x, which silently ignores it). Done before .npmrc is present, so this
# self-upgrade is not itself subject to the release-age filter.
RUN npm install -g npm@12.0.2

ENV NODE_ENV=production
WORKDIR /app

# .npmrc carries min-release-age=7, so the image build refuses to install any
# dependency published in the last 7 days — the same policy enforced in CI.
COPY package.json package-lock.json .npmrc ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --chown=node:node src ./src

USER node
EXPOSE 3000

CMD ["node", "src/server.js"]

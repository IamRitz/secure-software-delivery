FROM node:22.23.2-alpine3.24

# Patch base-image OS packages (notably openssl / libcrypto3 / libssl3) so the
# ECR scan-on-push deploy gate is not blocked by known base-image CVEs. Runs as
# root before dropping to the non-root user; effective once Alpine 3.24 has
# published the fixed package.
RUN apk --no-cache upgrade

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

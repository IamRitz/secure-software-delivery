FROM node:22.23.2-alpine3.24

# Patch base-image OS packages (notably openssl / libcrypto3 / libssl3) so the
# ECR scan-on-push deploy gate is not blocked by known base-image CVEs. Runs as
# root before dropping to the non-root user; effective once Alpine 3.24 has
# published the fixed package.
RUN apk --no-cache upgrade

ENV NODE_ENV=production
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --chown=node:node src ./src

USER node
EXPOSE 3000

CMD ["node", "src/server.js"]

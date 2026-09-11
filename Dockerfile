# Multi-stage build. The runtime image ships ONLY the Node runtime, the app's
# production dependencies, and the app source — no npm. This matters for the
# image scan: npm (bundled in the base image) carries its OWN vulnerable
# transitive dependencies (brace-expansion, ip-address, tar, ...) in
# /usr/local/lib/node_modules/npm. Those are not the app's dependencies — the
# app's node_modules is clean — but Trivy scans the whole image filesystem, so
# a bundled-npm CVE with a fix blocks the pre-push gate even though `npm` is
# never executed at runtime (CMD is `node`). `apk upgrade` cannot fix these
# (they are npm-managed, not apk-managed), so the durable fix is to not ship
# npm in the runtime image at all.

# ---- builder: needs npm to install the app's production dependencies --------
FROM node:22.23.2-alpine3.24 AS builder

# Pin npm to a version that supports min-release-age (the base image ships
# npm 10.x, which silently ignores it). Done before .npmrc is present, so this
# self-upgrade is not itself subject to the release-age filter.
RUN npm install -g npm@12.0.2

WORKDIR /app

# .npmrc carries min-release-age=7, so the build refuses to install any
# dependency published in the last 7 days — the same policy enforced in CI.
COPY package.json package-lock.json .npmrc ./
RUN npm ci --omit=dev && npm cache clean --force

# ---- runtime: the Node runtime only, npm removed ---------------------------
FROM node:22.23.2-alpine3.24

# Upgrade apk-managed OS packages to the latest patch available in the pinned
# Alpine 3.24 repo at build time (e.g. the OpenSSL libssl3/libcrypto3 fix). A
# rebuild picks up newly-published patches; a still-blocking OS CVE means the
# fixed package has not yet reached the 3.24 mirror.
#
# Then remove npm/npx/corepack: the runtime runs `node` only and never needs a
# package manager, so shipping one only adds its bundled dependencies (and their
# CVEs) to the scanned image.
RUN apk upgrade --no-cache \
  && rm -rf \
    /usr/local/lib/node_modules/npm \
    /usr/local/lib/node_modules/corepack \
    /usr/local/bin/npm \
    /usr/local/bin/npx \
    /usr/local/bin/corepack

ENV NODE_ENV=production
WORKDIR /app

# The app's production dependencies, installed and vetted in the builder stage.
COPY --from=builder --chown=node:node /app/node_modules ./node_modules
# package.json is required at runtime so Node honours "type": "module" (ESM).
COPY --chown=node:node package.json ./
COPY --chown=node:node src ./src

USER node
EXPOSE 3000

CMD ["node", "src/server.js"]

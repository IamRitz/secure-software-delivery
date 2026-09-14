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

# Node 24.21.0 bundles OpenSSL 3.5.8, verified 2026-09-13 by running
# node -p process.versions.openssl in this digest. Node 22.23.2 bundles
# vulnerable OpenSSL 3.5.7 statically; apk upgrade cannot replace it.

# ---- builder: needs npm to install the app's production dependencies --------
FROM node:24.21.0-alpine3.24@sha256:be80f76cf40ec8e42b9bec49f60a55e0660f30af58d3e5a25530785b30ea67e2 AS builder

# Pin npm to the version used for min-release-age enforcement. Done before
# .npmrc is present, so this self-upgrade is not subject to the release-age filter.
RUN npm install -g npm@12.0.2

WORKDIR /app

# .npmrc carries min-release-age=7, so the build refuses to install any
# dependency published in the last 7 days — the same policy enforced in CI.
COPY package.json package-lock.json .npmrc ./
RUN npm ci --omit=dev && npm cache clean --force

# ---- runtime: the Node runtime only, npm removed ---------------------------
FROM node:24.21.0-alpine3.24@sha256:be80f76cf40ec8e42b9bec49f60a55e0660f30af58d3e5a25530785b30ea67e2

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

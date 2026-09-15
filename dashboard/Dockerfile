# Dashboard fleet SOAR (UI Wazuh) — output standalone Next.js.
# Build: docker build -t soar-fleet-dashboard:latest ./dashboard
#
# FLEET_API_URL di-bake ke rewrites next.config.ts SAAT next build (destination
# rewrite statis, process.env di-resolve build-time, bukan runtime). Default
# host.docker.internal:8080 = tujuan kanonik dari container bridge ke
# fleet-monitor (host network 0.0.0.0:8080). Container standalone wajib
# --add-host host.docker.internal:host-gateway; compose sudah set extra_hosts.
# node:24-slim (glibc) untuk deps+builder: native module tailwind/lightningcss
# (.node glibc) build di glibc, tidak di alpine/musl (layer cache lama di
# alpine rusak -> "Cannot find module lightningcss.linux-x64-musl.node").
# Runner tetap alpine (kecil): output standalone hanya JS, tanpa native exec.
FROM node:24-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

FROM node:24-slim AS builder
ARG FLEET_API_URL=http://host.docker.internal:8080
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1 \
    FLEET_API_URL=${FLEET_API_URL}
RUN npm run build

FROM node:24-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0

RUN addgroup -S -g 1001 nodejs && adduser -S -u 1001 -G nodejs nextjs

COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3000/ >/dev/null || exit 1

CMD ["node", "server.js"]

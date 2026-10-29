# syntax=docker/dockerfile:1
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:22-alpine AS build
# Next.js bakes the /v1 proxy target in at build time: point it at the API's address as seen
# from this container (compose service name, or the Kubernetes Service).
ARG REKEY_API_URL=http://rekey-api:8000
ENV REKEY_API_URL=$REKEY_API_URL NEXT_TELEMETRY_DISABLED=1 NODE_OPTIONS=--max-old-space-size=4096
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:22-alpine
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
WORKDIR /app
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
COPY --from=build /app/public ./public
USER node
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=15s --retries=5 \
  CMD wget -qO- http://127.0.0.1:3000/ >/dev/null || exit 1
CMD ["node", "server.js"]

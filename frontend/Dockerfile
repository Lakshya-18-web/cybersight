# syntax=docker/dockerfile:1
# SOC triage console: static build served by an unprivileged nginx, which also forwards /api/* to the API service.
# Build:  docker build -t soc-ui:local frontend
# The image contains no secret. The analyst's token is typed into the browser at sign-in and never baked in.

FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
# `npm ci` when a lock file is committed (reproducible); `npm install` otherwise.
RUN if [ -f package-lock.json ]; then npm ci --no-audit --no-fund; else npm install --no-audit --no-fund; fi
COPY . .
# The browser calls this path on its own origin; nginx forwards it to the API. Only a path belongs here, never a credential.
ARG VITE_API_BASE_URL=/api
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080

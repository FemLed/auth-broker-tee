FROM node:20-alpine@sha256:f25b0e9d3d116e267d4ff69a3a99c0f4cf6ae94eadd87f1bf7bd68ea3ff0bef7

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --production --ignore-scripts

COPY src/ ./src/

ENV SOURCE_DATE_EPOCH=0
ENV NODE_ENV=production

LABEL "tee.launch_policy.log_redirect"="never"
LABEL "tee.launch_policy.allow_cmd_override"="false"
LABEL "tee.launch_policy.allow_env_override"="GOOGLE_CLIENT_ID,GOOGLE_CLIENT_SECRET,HMAC_SECRET,BROKER_API_KEY,GCP_SA_KEY,GCP_PROJECT_ID,REDIRECT_URI,GOOGLE_SCOPES,TLS_CERT_SECRET,TLS_KEY_SECRET,CLOUDFLARE_DNS_TOKEN,CLOUDFLARE_ZONE_ID"

EXPOSE 443
EXPOSE 8080

CMD ["node", "src/server.js"]

# ---- frontend build -------------------------------------------------------
FROM node:22-alpine AS web
WORKDIR /web
COPY frontend/package.json ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- runtime --------------------------------------------------------------
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TV_ENV=production TV_STATIC_DIR=/app/static
WORKDIR /app
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./
COPY --from=web /web/dist ./static
RUN useradd --system --uid 10001 tv && chown -R root:root /app && chmod -R a-w /app
USER tv
EXPOSE 8000
# boot.py applies migrations and restores the demo data with the owner
# credentials, then replaces itself with uvicorn WITHOUT them.
CMD ["python", "-m", "app.boot"]

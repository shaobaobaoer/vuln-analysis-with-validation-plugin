# Example Dockerfile: Node.js Web Application
# Use this as a template for Express/Koa/Fastify applications

FROM node:20-slim

WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm ci --production

# Copy application source
COPY . .

# Expose the application port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
    CMD curl -f http://localhost:3000/health || exit 1

# Start the application
CMD ["node", "index.js"]

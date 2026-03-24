FROM node:20-alpine

# Create app directory
WORKDIR /app

# Copy package.json and install dependencies
COPY package*.json ./
RUN npm install --ignore-scripts

# Copy source code and build
COPY . .
RUN npm run build

# Create logs directory
RUN mkdir -p /app/logs && chmod 777 /app/logs

# Default transport to SSE for Dokploy/Remote usage
ENV MCP_TRANSPORT="sse"
ENV PORT=8000
ENV HOST="0.0.0.0"

# Expose the default port
EXPOSE 8000

# Start the server (runs the compiled JavaScript)
CMD ["node", "dist/index.js"]

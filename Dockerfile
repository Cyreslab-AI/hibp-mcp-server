# Generated by https://smithery.ai. See: https://smithery.ai/docs/config#dockerfile
FROM node:lts-alpine

# Create app directory
WORKDIR /app

# Copy package files
COPY package.json ./
COPY tsconfig.json ./

# Install dependencies without running scripts (we run build explicitly)
RUN npm install --ignore-scripts

# Copy source files
COPY src ./src
COPY README.md ./

# Build the project
RUN npm run build

# Expose any required port if needed (not specified, so omitted)

# Run the MCP server
CMD ["node", "build/index.js"]

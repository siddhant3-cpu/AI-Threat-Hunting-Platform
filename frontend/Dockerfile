# Stage 1: Build the React application
FROM node:20-alpine AS build

WORKDIR /app

# Copy package descriptors and lockfile
COPY package*.json ./

# Install packages
RUN npm ci

# Copy source files
COPY . .

# Build production bundle
RUN npm run build

# Stage 2: Serve compiled assets via Nginx
FROM nginx:alpine

# Copy custom nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy build artifacts to Nginx html directory
COPY --from=build /app/dist /usr/share/nginx/html

# Expose HTTP port
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]

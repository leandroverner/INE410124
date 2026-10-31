# --- build ---
FROM node:24-alpine AS build
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npx ng build --configuration production

# --- runtime ---
FROM nginx:alpine
COPY --from=build /build/dist/frontend/browser /usr/share/nginx/html
EXPOSE 80

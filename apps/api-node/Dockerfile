# VULN: imagen base antigua, corre como root, sin HEALTHCHECK, secreto en ENV
FROM node:10
ENV JWT_SECRET=secreto
WORKDIR /app
COPY . .
RUN npm install
EXPOSE 3000
CMD ["node", "server.js"]

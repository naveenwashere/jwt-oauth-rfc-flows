FROM node:8-alpine

COPY . $WORKDIR

RUN npm install

EXPOSE 8080

CMD ["npm", "start"]

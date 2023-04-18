FROM golang:1.19.0

WORKDIR usr/local/app

COPY  . .

RUN go mod tidy

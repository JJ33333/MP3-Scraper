FROM alpine:3.21.3

WORKDIR /app
COPY . /app

RUN apk update && \
    apk add --no-cache \
      build-base=0.5-r3

RUN cd src && g++ main.cpp -o main
WORKDIR /app/src
CMD ["./main"]

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    gcc \
    make \
    libssl-dev \
    && apt-get clean

WORKDIR /app
RUN mkdir -p bin

COPY Makefile victim.h victim.c ./

RUN make victim

CMD ["./bin/victim-service"]
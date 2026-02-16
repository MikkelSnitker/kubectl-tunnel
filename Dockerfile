FROM alpine:latest

WORKDIR /scripts

RUN apk update && apk add socat iptables
COPY init.sh /scripts/

CMD [ "/scripts/init.sh" ]
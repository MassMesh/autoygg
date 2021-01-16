FROM golang:alpine

LABEL maintainer "Ward Vandewege <ward@jhvc.com>"

RUN set -ex \
 && apk --no-cache add \
    yggdrasil --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community \
 && apk --no-cache add bash build-base

COPY run-tests.sh /usr/bin/

ENTRYPOINT [ "/usr/bin/run-tests.sh" ]

FROM golang:alpine

LABEL maintainer "Ward Vandewege <ward@jhvc.com>"

# from yggdrasil 0.3.16, the post-install script tries to do `modprobe tun` which
# doesn't work in our docker build environment (no /lib/modules directory that matches
# the host kernel). So, we add || true to the apk commands (apparently subsequent apk
# commands also exit with an error code).
RUN set -ex \
 && apk --no-cache add \
    yggdrasil --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community || true \
 && apk --no-cache add bash build-base || true

RUN apk --no-cache add iptables || true

COPY run-tests.sh /usr/bin/

ENTRYPOINT [ "/usr/bin/run-tests.sh" ]

FROM registry.redhat.io/ubi8/go-toolset
USER root
WORKDIR /go/src/github.com/nalind/lukstool/
COPY / /go/src/github.com/nalind/lukstool/
RUN make clean all
FROM registry.redhat.io/ubi8/ubi-minimal
COPY --from=0 /go/src/github.com/nalind/lukstool/lukstool /usr/local/bin/

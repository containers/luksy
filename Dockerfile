FROM registry.fedoraproject.org/fedora
RUN dnf -y install golang make
WORKDIR /go/src/github.com/nalind/lukstool/
COPY / /go/src/github.com/nalind/lukstool/
RUN make clean all
FROM registry.fedoraproject.org/fedora-minimal
COPY --from=0 /go/src/github.com/nalind/lukstool/ /usr/local/bin/

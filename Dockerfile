FROM ubuntu:latest
RUN mkdir -p /opt/globalipd/bin
ADD ./go/bin/linux_amd64/globalipd /opt/globalipd/bin/globalipd
EXPOSE 4080
CMD /opt/globalipd/bin/globalipd

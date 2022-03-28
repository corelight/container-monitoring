FROM ubuntu:latest

MAINTAINER Al Smith <Al.Smith@corelight.com>
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update
RUN apt-get install -y python3 python3-pip

RUN pip install requests

COPY vxlan.py /vxlan.py
RUN chmod 755 vxlan.py

CMD ["/vxlan.py"]


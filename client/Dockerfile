FROM ubuntu:rolling

COPY ./ubuntu-requirements.txt /tmp/
RUN apt-get update && xargs -a /tmp/ubuntu-requirements.txt apt-get install -y

COPY python-requirements.txt /tmp/
RUN python3 -m pip install -r /tmp/python-requirements.txt

RUN mkdir /project
WORKDIR /project
ENTRYPOINT ["jupyter", "notebook", "--allow-root", "--no-browser"]
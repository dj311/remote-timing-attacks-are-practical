FROM ubuntu:rolling

COPY ./ubuntu-requirements.txt /tmp/
RUN apt-get update && xargs -a /tmp/ubuntu-requirements.txt apt-get install -y

COPY python-requirements.txt /tmp/
RUN python3 -m pip install -r /tmp/python-requirements.txt

COPY . /project

RUN cd /project && cc -shared -fPIC -o libtimedmessenger.so timed_messenger.c

WORKDIR /project
ENTRYPOINT ["python3", "attack.py"]
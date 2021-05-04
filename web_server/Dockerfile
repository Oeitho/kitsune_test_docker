FROM python:3.9.4-slim-buster
WORKDIR /app
EXPOSE 80
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y tshark iptables
RUN pip3 install scipy scapy pyshark numpy cython
COPY . .
CMD python3 main.py

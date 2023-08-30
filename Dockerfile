FROM ubuntu:22.04

ENV TZ=Europe/Madrid \
    DEBIAN_FRONTEND=noninteractive

# Install python3.8.15
RUN apt-get update && apt-get install -y software-properties-common
RUN add-apt-repository ppa:deadsnakes/ppa
RUN apt-get update && apt-get install -y python3.8 python3.8-dev python3.8-distutils python3.8-venv

# Install curl and network tools
RUN apt-get install -y curl net-tools

# Install pip
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
RUN python3.8 get-pip.py

# Install gcc and git
RUN apt-get update && apt-get install -y gcc git

WORKDIR /fedstellar
COPY requirements.txt .
# Install the required packages
RUN python3.8 -m pip install -r requirements.txt
RUN python3.8 -m pip install scikit-learn
RUN python3.8 -m pip install scikit-image
RUN python3.8 -m pip install seaborn
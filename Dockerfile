FROM ubuntu

RUN apt-get -y update && apt-get -y install sudo wget

RUN useradd syssec -m -G sudo -p ''

USER syssec
WORKDIR /home/syssec

COPY install.sh .

RUN bash -e install.sh

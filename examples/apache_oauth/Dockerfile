FROM ubuntu/apache2:latest

RUN apt-get update
RUN apt-get install -y \
    libapache2-mod-auth-openidc \
    apache2-utils

RUN a2enmod auth_openidc
RUN a2enmod ssl
RUN rm /etc/apache2/sites-enabled/000-default.conf
COPY index.html /var/www/html/index.html
COPY oauth2.conf /etc/apache2/sites-enabled/oauth2.conf

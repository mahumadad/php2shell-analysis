FROM php:8.1-fpm-bookworm

RUN echo "session.upload_progress.enabled = On"  >> /usr/local/etc/php/conf.d/php2shell.ini \
 && echo "session.upload_progress.cleanup = Off"  >> /usr/local/etc/php/conf.d/php2shell.ini \
 && echo "session.serialize_handler = php"        >> /usr/local/etc/php/conf.d/php2shell.ini \
 && echo "session.use_strict_mode = Off"          >> /usr/local/etc/php/conf.d/php2shell.ini \
 && echo "session.use_only_cookies = On"          >> /usr/local/etc/php/conf.d/php2shell.ini \
 && echo "display_errors = On"                    >> /usr/local/etc/php/conf.d/php2shell.ini \
 && echo "error_reporting = E_ALL"                >> /usr/local/etc/php/conf.d/php2shell.ini \
 && echo "allow_url_include = Off"                >> /usr/local/etc/php/conf.d/php2shell.ini

# Single FPM worker — guarantees PS(serializer) persistence across requests
RUN sed -i 's/^pm =.*/pm = static/'              /usr/local/etc/php-fpm.d/www.conf \
 && sed -i 's/^pm.max_children =.*/pm.max_children = 1/' /usr/local/etc/php-fpm.d/www.conf

RUN mkdir -p /var/lib/php/sessions /var/www/html/uploads \
 && chown -R www-data:www-data /var/lib/php/sessions /var/www/html/uploads

EXPOSE 9000

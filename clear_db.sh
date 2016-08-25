#!/bin/bash

rootpwd="toor"
path="$(cd "$(dirname "$0")" && pwd -P)"

echo "drop database vigilate;" | mysql -u root -p"$rootpwd"
echo "create database vigilate;" | mysql -u root -p"$rootpwd"

python3 $path/manage.py makemigrations vigilate_backend
python3 $path/manage.py makemigrations vulnerability_manager
python3 $path/manage.py migrate
python3 $path/manage.py migrate --run-syncdb

echo "Pushing Fixtures..."
python3 $path/manage.py loaddata offers

echo "Creating the superuser now..."
python3 $path/manage.py createsuperuser

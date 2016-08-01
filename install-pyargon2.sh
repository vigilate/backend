#!/bin/sh

SUDO=1

if [ $1 = "nosudo" ]
then
    SUDO=0
fi

set -ex
    

git submodule init
git submodule update
make -C module_com_bdd

if [ $SUDO -eq 1 ]
then
    sudo env PATH=$PATH make -C module_com_bdd install
else
    make -C module_com_bdd install
fi



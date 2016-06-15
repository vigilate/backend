#!/bin/sh

set -ex
    

git clone https://github.com/vigilate/module_com_bdd.git
make -C module_com_bdd
sudo env PATH=$PATH make -C module_com_bdd install

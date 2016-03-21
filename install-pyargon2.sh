#!/bin/sh

set -ex

PYTHON="python"
if [ $(python -c "import sys;print(sys.version.split('.', 1)[0])") -eq "2" ]
then
    PYTHON="python3"
fi
    

git clone https://github.com/vigilate/module_com_bdd.git
PYTHON=$PYTHON make -C module_com_bdd
sudo PYTHON=$PYTHON make -C module_com_bdd install

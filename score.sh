#!/bin/bash


DIR=/tmp/score

error_cleanup () {
    rm -rf $DIR
}
trap error_cleanup ERR


if [[ ! -e $DIR ]]; then
    apt install gcc make python3-dev python3-venv -y > /dev/null 2>&1
    mkdir -p $DIR
fi
GH="https://raw.githubusercontent.com/jbaldus/score_dev_env/main"

pushd $DIR 2>/dev/null
if [[ ! -e venv ]]; then
    python3 -m venv venv
    wget "$GH/requirements.txt" > /dev/null 2>&1
    source $DIR/venv/bin/activate
    pip install -r $DIR/requirements.txt
fi
source $DIR/venv/bin/activate
wget "$GH/score.py" -O $DIR/score.py > /dev/null 2>&1
python $DIR/score.py
popd
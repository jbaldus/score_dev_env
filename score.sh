#!/bin/bash

DIR=/tmp/score
mkdir -p $DIR
GH="https://raw.githubusercontent.com/jbaldus/score_dev_env/main"

pushd $DIR 2>/dev/null
if [[ ! -e venv ]]; then
    python3 -m venv venv
    wget "$GH/requirements.txt" > /dev/null 2>&1
    source $DIR/venv/bin/activate
    pip install -r $DIR/requirements.txt
fi
source $DIR/venv/bin/activate
wget "$GH/score.py" > /dev/null 2>&1
python $DIR/score.py
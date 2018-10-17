#!/bin/bash

# Something like this
result=./silencer prove $root $status $privkey $proof
./silencer verify $root $status $result

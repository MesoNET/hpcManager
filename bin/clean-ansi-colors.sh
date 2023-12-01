#!/bin/bash

/usr/bin/sed -r "s/\x1B\[(([0-9]{1,3};)*([0-9]{1,3})?)?[m,K,H,f,J]//g"
#!/bin/bash

for t in $(ls test_*); do echo -n $t; ./$t; done


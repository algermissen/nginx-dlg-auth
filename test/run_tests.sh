#!/bin/bash

for t in $(ls test_*); do echo $t; ./$t; done


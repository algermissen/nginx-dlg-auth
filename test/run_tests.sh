#!/bin/bash

for t in $(ls test_*); do 
  echo $t;
  ./$t;
  if [ $? -ne 0 ] ; then
    exit $?;
  fi;
done


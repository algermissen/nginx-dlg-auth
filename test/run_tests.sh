#!/bin/bash

for t in $(ls test_*); do 
  echo "TEST- ";
  echo $t;
  ./$t;
  if [ $? -ne 0 ] ; then
    echo "... failed"; 
    exit $?;
  fi;
done


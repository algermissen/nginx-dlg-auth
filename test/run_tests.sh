#!/bin/bash

rc=0
for t in $(ls test_*); do 
  echo $t;
  ./$t
  if [ $? -ne 0 ]; then
    rc=1
    echo "   *** $t FAILED ***"
  fi
  echo "RC: $rc"
done
exit $rc

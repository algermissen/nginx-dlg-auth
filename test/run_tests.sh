#!/bin/bash

rc=0
for t in $(ls test_*); do 
  echo $t;
  ./$t
  if[ $? -ne 0 ] ; then
    rc=$?
    echo "   *** $t FAILED ***"
  fi
done
exit $rc

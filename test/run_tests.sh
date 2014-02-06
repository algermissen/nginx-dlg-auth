#!/bin/bash

rc=0
for t in $(ls test_*); do 
  echo $t;
  ./$t || rc=$? && echo "   *** $t FAILED"
done
exit $rc

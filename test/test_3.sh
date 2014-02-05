#!/bin/bash

if [ `curl -v -s http://localhost/protected -w "%{http_code}" -o /dev/stderr` -ne 401 ] ; then echo "Expected 401"; exit 1;  fi


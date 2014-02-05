#!/bin/bash

if [ `curl -v -s http://localhost/unprotected -w "%{http_code}" -o /dev/stderr` -ne 200 ] ; then echo "Expected 200"; exit 1;  fi


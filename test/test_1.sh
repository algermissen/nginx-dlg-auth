#!/bin/bash

if [ `curl -s http://localhost/unprotected -w "%{http_code}" -o /dev/null` -ne 200 ] ; then echo "Expected 200"; exit 1;  fi


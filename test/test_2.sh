#!/bin/bash

if [ `curl -s -H "$AUTH" http://localhost:80/protected -w "%{http_code}"` -ne 200 ] ; then echo "Expected 200"; exit 1; ; fi


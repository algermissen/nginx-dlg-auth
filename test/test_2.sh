#!/bin/bash

echo $AUTH

curl -H 'Authorization: '$AUTH http://localhost:80/protected


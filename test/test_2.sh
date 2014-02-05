#!/bin/bash

echo $AUTH

curl -H $AUTH http://localhost:80/protected


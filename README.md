nginx-dlg-auth
==============

NGINX module for delegating authentication and authorization to an HTTP gateway.

Installation
============

This NGINX module needs [ciron](https://github.com/algermissen/ciron)
and [hawkc](https://github.com/algermissen/hawkc). Build them separately
and adjust nginx-dlg-auth's config file to point to libciron.a and libhawkc.a.

Also, copy the header files ciron.h and hawkc.h to a standard header file location
on your machine.

Configure NGINX build like this:


    ./configure --add-module=/Users/jan/Projects/NORD/ono/workspace/nginx-dlg-auth

You may also want to add the library file to $LINK_DEPS to make
sure nginx will correctly relink itself on make if library
changes."



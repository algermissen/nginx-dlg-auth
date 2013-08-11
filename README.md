nginx-dlg-auth
==============

NGINX module for delegating authentication and authorization to an HTTP gateway.

Status
======

nginx-dlg-auth is in pre-release state. There hasn't been any thorough testing
so far nor is there any production experience. However, this NGINX module will
be used in production shortly and then generate enough feedback to allow for
aiming at a public version 1.0.


Installation
============

Note: I am working on an ROM-install of NGINX including the module.

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

NGINX Module Configuration
==========================

    dlg_auth <realm> 

    dlg_auth_iron_pwd <password>  OR <passwordID> <password>

    dlg_auth_allowed_clock_skew <allowed-skew-in-seconds>

If dlg_auth is missing or if realm is 'off', the module will not be enabled.

You can use dlg_auth_iron_pwd to either set a single password, or to provide
a set of passwordIds and password to enable password rotation.

Examples

    dlg_auth ***REMOVED***
    dlg_auth_iron_pwd z3$0O1Y]8x3T+;
    dlg_auth_allowed_clock_skew 10



    dlg_auth ***REMOVED***
    dlg_auth_iron_pwd 100922 z3$0O1Y]8x3T+;
    dlg_auth_iron_pwd 776277 w1|6Q3V]7s8R);
    dlg_auth_iron_pwd 199289 i7(5P3D.4f0D-;
    dlg_auth_iron_pwd 662552 a6>0K0G]8z7B=;
    dlg_auth_allowed_clock_skew 10


You must not use passwords that contain ';' characters. This would probably confuse 
nginx config parser.












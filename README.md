nginx-dlg-auth
==============

NGINX module for delegating authentication and authorization to an HTTP gateway.



Notes
=====

"In file "config" you may add something like this:

CORE_LIBS="$CORE_LIBS -L /path/to/library -lxx"

or

CORE_LIBS="$CORE_LIBS /path/to/library/libxx.a"

You may also want to add the library file to $LINK_DEPS to make
sure nginx will correctly relink itself on make if library
changes."

----------
http://www.tekovic.com/adding-custom-modules-to-nginx-rpm
http://www.prateekn.com/2012/06/re-building-rpm-of-nginx-with-added.html
https://github.com/rebuy-de/nginx
----------

handle request:

  if not uri is protected:
    decline

  if principal required:
    add Gateway-Id header - really? why would I?
    make sure forwarded for header is set
    decline

  AuthorizationHeader authHeader = AuthorizationHeader.authorization(
             requestContext.getHeaderString(HttpHeaders.AUTHORIZATION));

  struct hawk_authorization_header h;
  



   URI uri = requestContext.getUriInfo().getRequestUri();
HawkContext hawk = HawkContext.request(requestContext.getMethod(), uri.getPath(),
                                       uri.getHost(), uri.getPort())
                     .credentials(id, password, algorithm)
                     .tsAndNonce(authHeader.getTs(), authHeader.getNonce())
                     .hash(authHeader.getHash()).build();

/*
 * Now we use the created Hawk to validate the HMAC sent by the client
 * in the Authorization header.
 */
if (!hawk.isValidMac(authHeader.getMac())) {
      LOG.log(Level.SEVERE, "Unable to validate HMAC signature");
      requestContext.abortWith(createDefault401Response());
      return;
}  


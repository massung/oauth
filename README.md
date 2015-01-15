# OAuth 1.0a for LispWorks

This is a simple implementation of [OAuth 1.0a](http://oauth.net/core/1.0) authentication flow and performing actions. It always uses HMAC-SHA1 signatures via the [`sha1`](http://github.com/massung/sha1) and the [`http`](http://github.com/massung/http) libraries.

## Quickstart

OAuth is difficult to show an example of, so keep in mind that these examples won't "just work" as they are calls to a fictitious site.

The OAuth package is - at its core - classes for OAuth requests and response tokens that are used to perform future requests.

To do anything, you'll need to make an `oauth-request` object, which is a subclass of an HTTP [`request`](https://github.com/massung/http/blob/master/http.lisp#L123), with the addition of a consumer key and consumer secret:

	CL-USER > (make-instance
               'oauth-request
               :key "my-app-key"
               :secret "my-app-secret"
               :method "POST"
               :url "https://site.com/request_token")
	#<OAUTH-REQUEST POST "https://site.com/request_token">

Once you have a request-token request, call `oauth-request-token`.

	CL-USER > (oauth-request-token *)
	#<OAUTH::OAUTH-AUTH-TOKEN "Ly8V3TzXM3201PyhkXTTZkISxlo2xlgd">

*Once you have an `oauth-auth-token`, the user needs to authorize your application. This is done differently by different sites, so there's no example of it here.* 

After the user has authorized your application, the `oauth-auth-token` needs to be turned into an `oauth-access-token`. This is done via another call with a new request.

	CL-USER > (make-instance
               'oauth-request
               :key "my-app-key"
               :secret "my-app-secret"
               :method "POST"
               :url "https://site.com/access_token")
	#<OAUTH-REQUEST POST "https://site.com/access_token">

	CL-USER > (oauth-request-access * auth-token)
	#<OAUTH::OAUTH-ACCESS-TOKEN "DmvnySLm6XjFpeyntJipiHQQTmkNu3HpJgV">

Once you have an access token, that's all that is needed to perform future requests with `oauth-perform-request`.

	(oauth-perform-request req access-token)

That's it!
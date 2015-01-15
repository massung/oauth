;;;; OAuth 1.0a for LispWorks
;;;;
;;;; Copyright (c) 2015 by Jeffrey Massung
;;;; All rights reserved.
;;;;
;;;; This file is provided to you under the Apache License,
;;;; Version 2.0 (the "License"); you may not use this file
;;;; except in compliance with the License.  You may obtain
;;;; a copy of the License at
;;;;
;;;;    http://www.apache.org/licenses/LICENSE-2.0
;;;;
;;;; Unless required by applicable law or agreed to in writing,
;;;; software distributed under the License is distributed on an
;;;; "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
;;;; KIND, either express or implied.  See the License for the
;;;; specific language governing permissions and limitations
;;;; under the License.
;;;;

(defpackage :oauth
  (:use :cl :lw :sha1 :http)
  (:export
   #:oauth-perform-request

   ;; token request functions
   #:oauth-request-token
   #:oauth-request-access

   ;; request methods
   #:oauth-request
   #:oauth-request-consumer-key
   #:oauth-request-consumer-secret

   ;; token methods
   #:oauth-token
   #:oauth-token-secret))

(in-package :oauth)

(defvar *oauth-nonce-count* 0
  "A forever-incrementing counter for OAuth requests.")

(defclass oauth-request (request)
  ((key    :initarg :key    :accessor oauth-request-consumer-key)
   (secret :initarg :secret :accessor oauth-request-consumer-secret))
  (:documentation "An OAuth HTTP request."))

(defclass oauth-token ()
  ((token  :initarg :token  :reader oauth-token)
   (secret :initarg :secret :reader oauth-token-secret))
  (:documentation "Authorization and access tokens."))

(defclass oauth-auth-token (oauth-token) ())
(defclass oauth-access-token (oauth-token) ())

(defmethod print-object ((token oauth-token) stream)
  "Display an OAuth token to a stream."
  (print-unreadable-object (token stream :type t)
    (prin1 (oauth-token token) stream)))

(defconstant +unix-epoch+ (encode-universal-time 0 0 0 1 1 1970 0)
  "OAuth timestamps are based from the Unix epoch.")

(defun oauth-timestamp ()
  "Return an OAuth (Unix) timestamp."
  (- (get-universal-time) +unix-epoch+))

(defun oauth-get-nonce (req)
  "Return a nonce for an OAuth request."
  (let ((key (oauth-request-consumer-key req)))
    (sha1-hex (format nil "~a-~a-~a" (incf *oauth-nonce-count*) (get-universal-time) key))))

(defmethod oauth-authorization-base-header (req token)
  "The required OAuth request headers, minus the oauth_signature."
  (list (list "oauth_consumer_key" (encode-url (oauth-request-consumer-key req)))
        (list "oauth_nonce" (oauth-get-nonce req))
        (list "oauth_timestamp" (oauth-timestamp))
        (list "oauth_signature_method" "HMAC-SHA1")
        (list "oauth_version" "1.0")))

(defmethod oauth-authorization-base-header (req (token oauth-access-token))
  "Access tokens are part of the authorization header."
  (cons (list "oauth_token" (oauth-token token)) (call-next-method)))

(defun oauth-signature-base-string (req base-header)
  "Append all the OAuth headers with the request parameters. Sort by key then value."
  (flet ((normalize (a b)
           (if (string= (first a) (first b))
               (string< (second a) (second b))
             (string< (first a) (first b)))))
    (let* ((url (request-url req))

           ;; strip the query and the fragment from the URL to get the base URL
           (base-url (encode-url (format-url (make-instance 'url
                                                            :scheme (url-scheme url)
                                                            :auth (url-auth url)
                                                            :domain (url-domain url)
                                                            :port (url-port url)
                                                            :path (url-path url)))))

           ;; combine all the parameters and sort them
           (params (sort (append (url-query url) (copy-list base-header)) #'normalize)))
      (format nil "~a&~a&~:{~a%3D~a~:^%26~}" (request-method req) base-url params))))

(defun oauth-authorization-header (req &optional token)
  "Return the HMAC-SHA1 signature for an OAuth request."
  (let* ((base-header (oauth-authorization-base-header req token))
         (base-string (oauth-signature-base-string req base-header))
         (token-secret (and token (oauth-token-secret token)))
         (sha1-key (format nil "~@[~a~]&~@[~a~]" (oauth-request-consumer-secret req) token-secret)))
    (cons (list "oauth_signature" (encode-url (hmac-sha1-base64 sha1-key base-string))) base-header)))

(defun oauth-authorization-string (req &optional token)
  "Return the OAuth authorization string."
  (with-output-to-string (s)
    (loop for (key value) in (oauth-authorization-header req token)
          for comma-p = (plusp (file-position s))
          do (format s "~:[OAuth ~;, ~]~a=\"~a\"" comma-p key value))))

(defun oauth-parse-response-token (resp class)
  "Return an authorization or access token from a response."
  (let ((qs (parse-query-string (response-body resp))))
    (make-instance class
                   :token (second (assoc "oauth_token" qs :test #'string=))
                   :secret (second (assoc "oauth_token_secret" qs :test #'string=)))))

(defun oauth-perform-request (req token &rest perform-args &key &allow-other-keys)
  "Perform an OAuth request and parse the token returned."
  (setf (http-header req "Authorization")
        (oauth-authorization-string req token))

  ;; send the request and return the response
  (apply #'http-perform req perform-args))

(defun oauth-request-token (req &rest perform-args &key &allow-other-keys)
  "Create and perform an OAuth request that should return a token."
  (with-response (resp (apply #'oauth-perform-request req nil perform-args))
    (oauth-parse-response-token resp 'oauth-auth-token)))

(defun oauth-request-access (req token &rest perform-args &key &allow-other-keys)
  "Convert an authorization token into an access token."
  (with-response (resp (apply #'oauth-perform-request req token perform-args))
    (oauth-parse-response-token resp 'oauth-access-token)))

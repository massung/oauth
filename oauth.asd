(defpackage :oauth-asd
  (:use :cl :asdf))

(in-package :oauth-asd)

(defsystem :oauth
  :name "oauth"
  :version "1.0"
  :author "Jeffrey Massung"
  :license "Apache 2.0"
  :description "OAuth 1.0a for LispWorks."
  :serial t
  :components ((:file "oauth"))
  :depends-on ("sha1" "http"))


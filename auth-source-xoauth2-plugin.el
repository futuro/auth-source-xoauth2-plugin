;; auth-source-xoauth2-plugin.el -- authentication source plugin for xoauth2 -*- lexical-binding: t -*-

;; Copyright (C) 2024 Xiyue Deng <manphiz@gmail.com>

;; Author: Xiyue Deng <manphiz@gmail.com>
;; Version: 0.1-git
;; Package-Requires: ((emacs "28.1") (oauth2 "0.17"))

;; This file is not part of GNU Emacs.

;; GNU Emacs is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; GNU Emacs is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with GNU Emacs.  If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:

;; This package enables support for xoauth2 authentication with
;; auth-source.  OAuth 2.0, which stands for “Open Authorization”, is a
;; standard designed to allow a website or application to access
;; resources hosted by other web apps on behalf of a user.  The OAuth
;; 2.0 Authorization Protocol Extensions (xoauth2) extend the OAuth 2.0
;; Authentication Protocol and the JSON Web Token (JWT) to enable
;; server-to-server authentication.  More info please check out:
;; https://stackoverflow.com/a/76389679/2337550

;; To set up, please put this file in the `load-path' of
;; Emacs, and add the following lines in your Emacs configuration:

;;     (require 'auth-source-xoauth2-plugin)
;;     (auth-source-xoauth2-plugin-enable)

;; or with use-package:

;;     (use-package auth-source-xoauth2-plugin
;;       :config
;;       (auth-source-xoauth2-plugin-enable))

;; After enabling, smtpmail should be supported.  To enable this in Gnus
;; nnimap, you should also set `(nnimap-authenticator xoauth2)' in the
;; corresponding account settings in `gnus-secondary-select-methods'

;; auth-source uses the `secret' field in auth-source file as password
;; for authentication, including xoauth2.  To decide which
;; authentication method to use (e.g. plain password vs xoauth2), it
;; inspects the `auth' field from the auth-source entry, and if the
;; value is `xaouth2', it will try to gather data and get the access
;; token for use of xoauth2 authentication; otherwise, it will fallback
;; to the default authentication method.

;; When xoauth2 authentication is enabled, it will try to get the
;; following data from the auth-source entry: `auth-url', `token-url',
;; `scope', `client-id', `client-secret', `redirect-uri', and optionally
;; `state'.  These information will be used by oauth2 to retrieve the
;; access-token.  This package uses an advice to switch the auth-source
;; search result from the `password' to the `access-token' it got, which
;; in turn will be used to construct the xoauth2 authentication string,
;; currently in nnimap-login and smtpmail-try-auth-method.  To really
;; enable xoauth2 in smtpmail, it will add 'xoauth2 to
;; 'smtpmail-auth-supported (if it is not already in the list) using
;; `add-to-list' so that xoauth2 is tried first.

;; Note that currently the auth-source requires the searched entry must
;; have `secret' field set in the entry, which is not necessary when
;; using xoauth2.  Therefore in the advice it temporarily disables
;; checking for `:secret' if set and perform the search, and check the
;; result before returning.

;;; Code:

(require 'auth-source)
(require 'cl-lib)
(require 'map)
(require 'oauth2)
(require 'smtpmail)

(defun auth-source-xoauth2-plugin--search-backends (orig-fun &rest args)
  "Perform `auth-source-search' and set password as access-token when requested.
Calls ORIG-FUN which would be `auth-source-search-backends' with
ARGS to get the auth-source-entry.  The substitution only happens
if one sets `auth' to `xoauth2' in your auth-source-entry.  It is
expected that `token_url', `client_id', `client_secret', and
`refresh_token' are properly set along `host', `user', and
`port' (note the snake_case)."
  (auth-source-do-trivia "Advising auth-source-search")
  (let (check-secret)
    (when (memq :secret (nth 5 args))
      (auth-source-do-trivia
       "Required fields include :secret.  As we are requesting access token to replace the secret, we'll temporary remove :secret from the require list and check that it's properly set to a valid access token later.")
      (setf (nth 5 args) (remove :secret (nth 5 args)))
      (setq check-secret t))
    (let ((orig-res (apply orig-fun args))
          res)
      (dolist (auth-data orig-res)
        (auth-source-do-trivia "Matched auth data: %s" (pp-to-string auth-data))
        (let ((auth (plist-get auth-data :auth)))
          (when (equal auth "xoauth2")
            (auth-source-do-debug
             ":auth set to `xoauth2'.  Will get access token.")
            (map-let ((:auth-url auth-url)
                      (:token-url token-url)
                      (:scope scope)
                      (:client-d client-id)
                      (:client-secret client-secret)
                      (:redirect-uri redirect-uri)
                      (:state state))
                auth-data
              (auth-source-do-debug "Using oauth2 to auth and store token...")
              (let ((token (oauth2-auth-and-store
                            auth-url token-url scope client-id client-secret
                            redirect-uri state)))
                (auth-source-do-trivia "oauth2 token: %s" (pp-to-string token))
                (auth-source-do-debug "Refreshing token...")
                (oauth2-refresh-access token)
                (auth-source-do-debug "Refresh successful.")
                (auth-source-do-trivia "oauth2 token after refresh: %s"
                                       (pp-to-string token))
                (let ((access-token (oauth2-token-access-token token)))
                  (auth-source-do-trivia
                   "Updating :secret with access-token: %s" access-token)
                  (setq auth-data
                        (plist-put auth-data :secret access-token)))))))

        (unless (and check-secret
                     (not (plist-get auth-data :secret)))
          (auth-source-do-debug "Updating auth-source-search results.")
          (push 'res auth-data)))
      res)))

;;;###autoload
(defun auth-source-xoauth2-plugin-enable ()
  "Enable auth-source-xoauth2-plugin."
  (unless (memq 'xoauth2 smtpmail-auth-supported)
    (push 'xoauth2 smtpmail-auth-supported))

  (advice-add #'auth-source-search-backends :around
              #'auth-source-xoauth2-plugin--search-backends))

(provide 'auth-source-xoauth2-plugin)

;;; auth-source-xoauth2-plugin.el ends here

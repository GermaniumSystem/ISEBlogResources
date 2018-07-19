#!/usr/bin/env python

import base64
import hashlib
import hmac
import re

from datetime import datetime
from burp import IBurpExtender
from burp import IHttpListener

PASSWORD = 'Password1!' #CHANGEME

# Highlight color codes:
# Green   - New auth header generated.
# Yellow  - New auth header using session key.
# Red     - Generation canceled, numerical user but no session key.
# Pink    - Session key request found, no key yet.
# Magenta - Session key found.


class BurpExtender(IBurpExtender, IHttpListener):

    def __init__(self):
        self.session_key = None

    def registerExtenderCallbacks(self, callbacks):
        print("Plugin can into life!")
        print("Make sure you reload the NAS web page! Failure to do so will cause a bad time.")
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("HMAC-SHA1-DATE")
        callbacks.registerHttpListener(self)


    def processHttpMessage(self, tool_flag, message_is_request, current_request):
        request_info = self._helpers.analyzeRequest(current_request)
        headers = request_info.getHeaders()
        url = request_info.getUrl()
        path = url.getPath()
        query = url.getQuery()
        if not message_is_request:
            #print(path)
            # Some portions of the API use a session key.
            # This key is distributed by '/apps/filebrowser/auths/seagate.callback' and needs to be
            # intercepted and saved so we can generate headers with it.
            # Note: This plugin must be active when this key is retrieved. It the plugin is loaded
            # mid-session, you will need to log out and back it.
            if ('/apps/filebrowser/auths/seagate.callback') in path.lower():
                print("Found callback!")
                current_request.setHighlight("pink")
                response_str = self._helpers.bytesToString(current_request.getResponse())
                key_search = re.search('"session_key": *"([^"]+)"', response_str, re.I)
                if key_search:
                    print("Found session key!")
                    current_request.setHighlight("magenta")
                    self.session_key = key_search.group(1)
            return
  
        if not _containsAuthHeader(headers):
            return

        method = request_info.getMethod()
        #if method is "GET":
        #    #TODO: Some GET requests seem to require the HMAC as a param, but I don't yet know how it calculates the HMAC.
        #    print("Skipping GET")
        #    return
        #else:
        #    print("Continuing with method: " + method)

        request_str = self._helpers.bytesToString(current_request.getRequest())
        if query is not None:
            path = path + "?" + query
        body_bytes = current_request.getRequest()[request_info.getBodyOffset():]
        body_str = self._helpers.bytesToString(body_bytes)

        date = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT") # Wants GMT for some reason.
        # The SHA1 sum of the user's password is used as the secret key for HMAC generation. (Unless it's a numerical session)
        password_sha1sum = hashlib.sha1(bytes(PASSWORD)).hexdigest()

        # Some portions of the API use a weird username (e.g. '3'). To deal with this, just pull the username from the existing header.
        username_b64 = _extractUsername(headers)
        username = str(base64.b64decode(bytes(username_b64)))
        # Numerical users are used to represent sessions. They require a special key and are a right PITA. The key will be used as the secret key for HMAC generation.
        numerical_username = username.isdigit()
        if numerical_username:
            if self.session_key is not None:
                #print("username is numerical - using session key.")
                password_sha1sum = self.session_key
            else:
                print("username is numerical but no session key has been intercepted! Cancelling modifications...")
                current_request.setHighlight("red")
                return

        # The important bit. Put it all together and HMAC it.
        hmac_msg = method + ' ' + path + '\n' + "Date: " + date + '\n' + body_str
        hmac = _makeDigest(hmac_msg, password_sha1sum)

        headers_new = []
        for header in list(headers):
            # Discard the old auth-related headers.
            if not (header.upper().startswith("DATE-AUTH: ") or header.upper().startswith("AUTHENTICATION: HMAC-SHA1-DATE ")):
                #print("Added header: " + header)
                headers_new.append(header)
            #else:
            #    print("Skipped header: " + header)

        headers_new.append("DATE-AUTH: " + date)
        headers_new.append("AUTHENTICATION: HMAC-SHA1-DATE " + username_b64 + ":" + hmac)
        #print(headers_new)

        new_message = self._helpers.buildHttpMessage(headers_new, body_str)
        #print("----")
        #print(hmac_msg)
        #print("--")
        #print(hmac)
        #print("--")
        #print(self._helpers.bytesToString(new_message))
        #print("----\n")
        if numerical_username:
            current_request.setHighlight("yellow")
        else:
            current_request.setHighlight("green")
        current_request.setRequest(new_message)
        #print("Modified request to " + path + " on " + date)
        return



def _makeDigest(message, key):
    ''' Generate a SHA1 HMAC using the provided message and secret key. Returns the HMAC signature.'''
    key = bytes(key)
    message = bytes(message)

    digester = hmac.new(key, message, hashlib.sha1)

    signature1 = digester.digest()
    signature2 = base64.b64encode(signature1)    

    return str(signature2)


def _containsAuthHeader(headers):
    for header in headers:
        if header.upper().startswith("DATE-AUTH: ") or header.upper().startswith("AUTHENTICATION: HMAC-SHA1-DATE "):
            return True
    return False


def _extractUsername(headers):
    for header in headers:
        if header.upper().startswith("AUTHENTICATION: HMAC-SHA1-DATE "):
            user_search = re.search("AUTHENTICATION: HMAC-SHA1-DATE (.*):", header, re.I)
            if user_search:
                username_b64 = user_search.group(1)
                if username_b64 is None:
                    raise LookupError("Lost username! Header: " + header)
                else:
                    return(username_b64)
            else:
                raise LookupError("Lost username! Header: " + header)

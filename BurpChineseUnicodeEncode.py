#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : T4erg
# @email   : T4erg#foxmail.com
# @Site    : https://blog.tinydawn.com/
# @File    : BurpChineseUnicodeEncode.py
# @Time    : 20/8/2017 9:40 PM
from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IResponseInfo

import re
# Class BurpExtender (Required) contaning all functions used to interact with Burp Suite API

print("""# @Author  : T4erg
# @email   : T4erg#foxmail.com
# @Site    : https://blog.tinydawn.com/
# @File    : BurpChineseUnicodeEncode.py
# @Time    : 20/8/2017 9:40 PM

# @Version  : 0.2.2
    """)

class BurpExtender(IBurpExtender, IHttpListener):

    # define registerExtenderCallbacks: From IBurpExtender Interface
    def registerExtenderCallbacks(self, callbacks):

        # keep a reference to our callbacks object (Burp Extensibility Feature)
        self._callbacks = callbacks
        # obtain an extension helpers object (Burp Extensibility Feature)
        # http://portswigger.net/burp/extender/api/burp/IExtensionHelpers.html
        self._helpers = callbacks.getHelpers()
        # set our extension name that will display in Extender Tab
        self._callbacks.setExtensionName("unicode decode")
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)

    # define processHttpMessage: From IHttpListener Interface
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

        # determine what tool we would like to pass though our extension:
        if toolFlag == 64 or toolFlag == 16 or toolFlag == 32:# or toolFlag == callbacks.TOOL_REPEATER:
            # determine if request or response:
            if not messageIsRequest:#only handle responses
                response = messageInfo.getResponse()
                analyzedResponse = self._helpers.analyzeResponse(response)
                headers = analyzedResponse.getHeaders()
                new_headers = []
                for header in headers:
                    if header is not None:
                        re.sub(r"iso-8859-1|GBK", "UTF-8", header, flags=re.I)
                        new_headers.append(header)
                print(new_headers)
                body = response[analyzedResponse.getBodyOffset():]
                body_string = body.tostring()
                body_string=body_string.decode("unicode_escape").encode("utf8")
                messageInfo.setResponse(self._helpers.buildHttpMessage(new_headers,
                                        self._helpers.bytesToString(body_string)))

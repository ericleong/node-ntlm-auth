# node-ntlm-auth: NTLM session response authentication client

## Introduction

This library enables communication with an NTLM server using the session
response protocol. 

## Authentication

NTLM HTTP Authentication headers are Base64-encoded packed structures of
three basic varieties.  Type 1 & 3 are sent from the client to the server,
and Type 2 is from server to client.

Because of how node.js handles keep-alive, the requests are handled by this
library, as long as the Type 1 message is provided. The Type 1 message
can be generated using node-smbhash or a similar library.

A request is made by providing the host, path, authentication information, 
and the Type 1 message. The response by the server to the Type 3 message 
is the callback.

### API

| parameter | value |
| --- | --- |
| secure | `true` if https, http otherwise |
| options | http(s) request options (including hostname, path, etc.)
| body | request body |
| auth | authentication parameters (see example) |
| type1_msg | initial type 1 message (can usually be sniffed) |
| callback | function to parse the response object |

### Example

```javascript
var ntlmRequest = require('./ntlm-auth.js').ntlmRequest;

ntlmRequest(true, requestOptions, body,
	{
		username: 'user', 
		workstation: 'workstation',
		domain: 'domain',
		password: 'password'
	},
	'type_1_message',
	function(resp) {
		resp.setEncoding('utf8');
		resp.on('data', function (chunk) {
			console.log(chunk);
		}
		
		resp.destroy();
	);
});
```

## Acknowledgements 

	This library is based off of python-ntlm
	http://code.google.com/p/python-ntlm/
	
	As well as functions from node-smbhash
	https://github.com/jclulow/node-smbhash

## References

	The NTLM Authentication Protocol and Security Support Provider
	Copyright (C) 2003, 2006 Eric Glass
	http://davenport.sourceforge.net/ntlm.html
	
	NTLM Authentication Scheme for HTTP
	Ronald Tschalaer / 17. June 2003
	http://www.innovation.ch/personal/ronald/ntlm.html

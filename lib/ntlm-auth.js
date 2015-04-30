// This library is free software: you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library.  if (not, see <http)//www.gnu.org/licenses/> or <http://www.gnu.org/licenses/lgpl.txt>.

'use strict';

var deepcopy = require('deepcopy'),
	async = require('async'),
	http = require('http'),
	https = require('https'),
	ntlm = require('./ntlm.js');

function ntlmRequest(secure, options, body, auth, type1_msg, cb) {
	// auth = 	{
	// 				username: <login username>,
	//				workstation: <workstation name>,
	//				domain: <domain of workstation>,
	//				password: <login password>
	//			}
	// type1_msg is the NTLM Type 1 message to send to the server
	// it can usually be sniffed and reused.

	var protocol = secure ? https : http;

	// need to only use a single socket so that connection is reused
	var agent = new protocol.Agent({
		keepAlive: true,
		maxSockets: 1 
	});
	
	async.waterfall([
		function(callback) {

			var reqOptions = deepcopy(options);

			reqOptions.agent = agent;
			reqOptions['headers'] = (reqOptions['headers'] || {});
			reqOptions['headers']['Authorization'] = 'NTLM ' + type1_msg;

			var req = protocol.request(reqOptions, function(resp) {
				var str = '';

				// another chunk of data has been recieved, so append it to `str`
				resp.on('data', function (chunk) {
					str += chunk;
				});

				// the whole resp has been recieved, so we just print it out here
				resp.on('end', function () {
					callback(null, resp);
				});
			});

			req.on('error', function(err) {
				console.error('error connecting');
				if (err) {
					console.error(err.stack);
				}
			});

			req.end();
		}
		], 
		function(err, resp) {
			var m;
			// Extract Type 2 from HTTP Response header, and use it here:
			if ('www-authenticate' in resp.headers) {
				m = resp.headers['www-authenticate'].match(/^NTLM (.*)$/);
			} else if ('proxy-authenticate' in resp.headers){
				m = resp.headers['proxy-authenticate'].match(/^NTLM (.*)$/);
			}

			if (m) {
				var parsed = ntlm.parse_NTLM_CHALLENGE_MESSAGE(m[1]);
				var msg3 = ntlm.create_NTLM_AUTHENTICATE_MESSAGE(
						parsed.ServerChallenge, 
						auth.username, auth.workstation, auth.domain, auth.password, parsed.NegotiateFlags);

				var reqOptions = deepcopy(options);

				reqOptions.agent = agent;
				reqOptions['headers'] = (reqOptions['headers'] || {});
				reqOptions['headers']['Authorization'] = 'NTLM ' + msg3;
				
				if (body) {
					reqOptions['headers']['Content-Length'] = body.length;
				}

				var req = protocol.request(reqOptions, cb);

				req.on('error', function(err) {
					console.error('error connecting');
					if (err) {
						console.error(err.stack);
					}
				});

				if (body) {
					req.write(body);
				}

				req.end();
			} else {
				console.error('server did not respond with a type 2 response!');
				console.error(resp.statusCode);
			}
		}
	);
}

module.exports.ntlmRequest = ntlmRequest;
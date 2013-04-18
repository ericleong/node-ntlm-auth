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

var http = require('http'),
	async = require('async'),
	keepAliveAgent = require('keep-alive-agent'),
    ntlm = require('./ntlm.js');

function ntlmRequest(host, path, auth, type1_msg, callback) {
	// auth = 	{
	// 				username: <login username>,
	//				workstation: <workstation name>,
	//				domain: <domain of workstation>,
	//				password: <login password>
	//			}
	// type1_msg is the NTLM Type 1 message to send to the server
	// it can usually be sniffed and reused.
	
	// need to only use a single socket so that connection is reused
	var agent = new keepAliveAgent({ maxSockets: 1 });
	
	async.waterfall([
			function(callback) {
				http.get({
					hostname: host,
					path: path,
					headers: {
						'Authorization': 'NTLM ' + type1_msg,
						Connection: 'keep-alive',
					},
					agent: agent
				}, function(resp) {
					resp.on('data', function (chunk) {
						// consume data (so the http connection closes)
					});
					
					callback(null, resp);
				});
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
				
				var parsed = ntlm.parse_NTLM_CHALLENGE_MESSAGE(m[1]);
				var msg3 = ntlm.create_NTLM_AUTHENTICATE_MESSAGE(
						parsed.ServerChallenge, 
						auth.username, auth.workstation, auth.domain, auth.password, parsed.NegotiateFlags);

				http.get({
					hostname: host,
					path: path,
					headers: {
						'Authorization': 'NTLM ' + msg3,
						Connection: 'keep-alive',
					},
					agent: agent
				}, callback);
			}
	);
}

module.exports.ntlmRequest = ntlmRequest;
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

// - Javascript translation of python-ntlm
// http://code.google.com/p/python-ntlm/
// - Uses parts of node-smbhash
// https://github.com/jclulow/node-smbhash

var $ = require('./common');
var crypto = require('crypto'); 
var lmhashbuf = require('./smbhash').lmhashbuf;
var nthashbuf = require('./smbhash').nthashbuf;

NTLM_NegotiateUnicode                =  0x00000001;
NTLM_NegotiateOEM                    =  0x00000002;
NTLM_RequestTarget                   =  0x00000004;
NTLM_Unknown9                        =  0x00000008;
NTLM_NegotiateSign                   =  0x00000010;
NTLM_NegotiateSeal                   =  0x00000020;
NTLM_NegotiateDatagram               =  0x00000040;
NTLM_NegotiateLanManagerKey          =  0x00000080;
NTLM_Unknown8                        =  0x00000100;
NTLM_NegotiateNTLM                   =  0x00000200;
NTLM_NegotiateNTOnly                 =  0x00000400;
NTLM_Anonymous                       =  0x00000800;
NTLM_NegotiateOemDomainSupplied      =  0x00001000;
NTLM_NegotiateOemWorkstationSupplied =  0x00002000;
NTLM_Unknown6                        =  0x00004000;
NTLM_NegotiateAlwaysSign             =  0x00008000;
NTLM_TargetTypeDomain                =  0x00010000;
NTLM_TargetTypeServer                =  0x00020000;
NTLM_TargetTypeShare                 =  0x00040000;
NTLM_NegotiateExtendedSecurity       =  0x00080000;
NTLM_NegotiateIdentify               =  0x00100000;
NTLM_Unknown5                        =  0x00200000;
NTLM_RequestNonNTSessionKey          =  0x00400000;
NTLM_NegotiateTargetInfo             =  0x00800000;
NTLM_Unknown4                        =  0x01000000;
NTLM_NegotiateVersion                =  0x02000000;
NTLM_Unknown3                        =  0x04000000;
NTLM_Unknown2                        =  0x08000000;
NTLM_Unknown1                        =  0x10000000;
NTLM_Negotiate128                    =  0x20000000;
NTLM_NegotiateKeyExchange            =  0x40000000;
NTLM_Negotiate56                     =  0x80000000;

// we send these flags with our type 1 message
NTLM_TYPE1_FLAGS = (NTLM_NegotiateUnicode | 
                    NTLM_NegotiateOEM | 
                    NTLM_RequestTarget | 
                    NTLM_NegotiateNTLM | 
                    NTLM_NegotiateOemDomainSupplied | 
                    NTLM_NegotiateOemWorkstationSupplied | 
                    NTLM_NegotiateAlwaysSign | 
                    NTLM_NegotiateExtendedSecurity | 
                    NTLM_NegotiateVersion | 
                    NTLM_Negotiate128 | 
                    NTLM_Negotiate56 ) >>> 0; // unsigned
NTLM_TYPE2_FLAGS = (NTLM_NegotiateUnicode | 
                    NTLM_RequestTarget | 
                    NTLM_NegotiateNTLM | 
                    NTLM_NegotiateAlwaysSign | 
                    NTLM_NegotiateExtendedSecurity | 
                    NTLM_NegotiateTargetInfo | 
                    NTLM_NegotiateVersion | 
                    NTLM_Negotiate128 | 
                    NTLM_Negotiate56) >>> 0; // unsigned

NTLM_MsvAvEOL             = 0; // Indicates that this is the last AV_PAIR in the list. AvLen MUST be 0. This type of information MUST be present in the AV pair list.
NTLM_MsvAvNbComputerName  = 1; // The server's NetBIOS computer name. The name MUST be in Unicode, and is not null-terminated. This type of information MUST be present in the AV_pair list.
NTLM_MsvAvNbDomainName    = 2; // The server's NetBIOS domain name. The name MUST be in Unicode, and is not null-terminated. This type of information MUST be present in the AV_pair list.
NTLM_MsvAvDnsComputerName = 3; // The server's Active Directory DNS computer name. The name MUST be in Unicode, and is not null-terminated.
NTLM_MsvAvDnsDomainName   = 4; // The server's Active Directory DNS domain name. The name MUST be in Unicode, and is not null-terminated.
NTLM_MsvAvDnsTreeName     = 5; // The server's Active Directory (AD) DNS forest tree name. The name MUST be in Unicode, and is not null-terminated.
NTLM_MsvAvFlags           = 6; // A field containing a 32-bit value indicating server or client configuration. 0x00000001: indicates to the client that the account authentication is constrained. 0x00000002: indicates that the client is providing message integrity in the MIC field (section 2.2.1.3) in the AUTHENTICATE_MESSAGE.
NTLM_MsvAvTimestamp       = 7; // A FILETIME structure ([MS-DTYP] section 2.3.1) in little-endian byte order that contains the server local time.<12>
NTLM_MsAvRestrictions     = 8; //A Restriction_Encoding structure (section 2.2.2.2). The Value field contains a structure representing the integrity level of the security principal, as well as a MachineID created at computer startup to identify the calling machine. <13>


/*
utility functions for Microsoft NTLM authentication

References:
[MS-NLMP]: NT LAN Manager (NTLM) Authentication Protocol Specification
http://download.microsoft.com/download/a/e/6/ae6e4142-aa58-45c6-8dcf-a657e5900cd3/%5BMS-NLMP%5D.pdf

[MS-NTHT]: NTLM Over HTTP Protocol Specification
http://download.microsoft.com/download/a/e/6/ae6e4142-aa58-45c6-8dcf-a657e5900cd3/%5BMS-NTHT%5D.pdf

Cntlm Authentication Proxy
http://cntlm.awk.cz/

NTLM Authorization Proxy Server
http://sourceforge.net/projects/ntlmaps/

Optimized Attack for NTLM2 Session Response
http://www.blackhat.com/presentations/bh-asia-04/bh-jp-04-pdfs/bh-jp-04-seki.pdf
*/

function dump_NegotiateFlags(NegotiateFlags) {
    if (NegotiateFlags & NTLM_NegotiateUnicode)
        console.log("NTLM_NegotiateUnicode set");
    if (NegotiateFlags & NTLM_NegotiateOEM)
        console.log("NTLM_NegotiateOEM set"                   );
    if (NegotiateFlags & NTLM_RequestTarget)
        console.log("NTLM_RequestTarget set"                  );
    if (NegotiateFlags & NTLM_Unknown9)
        console.log("NTLM_Unknown9 set"                       );
    if (NegotiateFlags & NTLM_NegotiateSign)
        console.log("NTLM_NegotiateSign set"                  );
    if (NegotiateFlags & NTLM_NegotiateSeal)
        console.log("NTLM_NegotiateSeal set"                  );
    if (NegotiateFlags & NTLM_NegotiateDatagram)
        console.log("NTLM_NegotiateDatagram set"              );
    if (NegotiateFlags & NTLM_NegotiateLanManagerKey)
        console.log("NTLM_NegotiateLanManagerKey set");
    if (NegotiateFlags & NTLM_Unknown8)
        console.log("NTLM_Unknown8 set"                       );
    if (NegotiateFlags & NTLM_NegotiateNTLM)
        console.log("NTLM_NegotiateNTLM set"                  );
    if (NegotiateFlags & NTLM_NegotiateNTOnly)
        console.log("NTLM_NegotiateNTOnly set"                );
    if (NegotiateFlags & NTLM_Anonymous)
        console.log("NTLM_Anonymous set"                      );
    if (NegotiateFlags & NTLM_NegotiateOemDomainSupplied)
        console.log("NTLM_NegotiateOemDomainSupplied set"     );
    if (NegotiateFlags & NTLM_NegotiateOemWorkstationSupplied)
        console.log("NTLM_NegotiateOemWorkstationSupplied set");
    if (NegotiateFlags & NTLM_Unknown6)
        console.log("NTLM_Unknown6 set"                       );
    if (NegotiateFlags & NTLM_NegotiateAlwaysSign)
        console.log("NTLM_NegotiateAlwaysSign set"            );
    if (NegotiateFlags & NTLM_TargetTypeDomain)
        console.log("NTLM_TargetTypeDomain set"               );
    if (NegotiateFlags & NTLM_TargetTypeServer)
        console.log("NTLM_TargetTypeServer set"               );
    if (NegotiateFlags & NTLM_TargetTypeShare)
        console.log("NTLM_TargetTypeShare set"                );
    if (NegotiateFlags & NTLM_NegotiateExtendedSecurity)
        console.log("NTLM_NegotiateExtendedSecurity set"      );
    if (NegotiateFlags & NTLM_NegotiateIdentify)
        console.log("NTLM_NegotiateIdentify set"              );
    if (NegotiateFlags & NTLM_Unknown5)
        console.log("NTLM_Unknown5 set"                       );
    if (NegotiateFlags & NTLM_RequestNonNTSessionKey)
        console.log("NTLM_RequestNonNTSessionKey set"         );
    if (NegotiateFlags & NTLM_NegotiateTargetInfo)
        console.log("NTLM_NegotiateTargetInfo set"            );
    if (NegotiateFlags & NTLM_Unknown4)
        console.log("NTLM_Unknown4 set"                       );
    if (NegotiateFlags & NTLM_NegotiateVersion)
        console.log("NTLM_NegotiateVersion set"               );
    if (NegotiateFlags & NTLM_Unknown3)
        console.log("NTLM_Unknown3 set"                       );
    if (NegotiateFlags & NTLM_Unknown2)
        console.log("NTLM_Unknown2 set"                       );
    if (NegotiateFlags & NTLM_Unknown1)
        console.log("NTLM_Unknown1 set"                       );
    if (NegotiateFlags & NTLM_Negotiate128)
        console.log("NTLM_Negotiate128 set"                   );
    if (NegotiateFlags & NTLM_NegotiateKeyExchange)
        console.log("NTLM_NegotiateKeyExchange set"           );
    if (NegotiateFlags & NTLM_Negotiate56)
        console.log("NTLM_Negotiate56 set");
}

function parse_NTLM_CHALLENGE_MESSAGE(msg2) {
    msg2 = new Buffer(msg2, 'base64');
    
//    var msg_type = msg2.readUInt32LE(8);
//    var TargetNameLen = msg2.readUInt16LE(12);
//    var TargetNameMaxLen = msg2.readUInt16LE(14);
//    var TargetNameOffset = msg2.readUInt32LE(16);
//    var TargetName = msg2.slice(TargetNameOffset, TargetNameOffset+TargetNameMaxLen);
    
    var NegotiateFlags = msg2.readUInt32LE(20);
    var ServerChallenge = msg2.slice(24, 32);
//    var Reserved = msg2.slice(32, 40);
    if (NegotiateFlags & NTLM_NegotiateTargetInfo) {
        TargetInfoLen = msg2.readUInt16LE(40);
        TargetInfoMaxLen = msg2.readUInt16LE(42, 44);
        TargetInfoOffset = msg2.readUInt32LE(44, 48);
        TargetInfo = msg2.slice(TargetInfoOffset, TargetInfoOffset+TargetInfoLen);
        var i=0;
        TimeStamp = '\0\0\0\0\0\0\0\0';
        while(i<TargetInfoLen) {
            var AvId = TargetInfo.readUInt16LE(i);
            var AvLen = TargetInfo.readUInt16LE(i+2);
            var AvValue = TargetInfo.slice(i+4, i+4+AvLen);
            i = i+4+AvLen;
            if (AvId == NTLM_MsvAvTimestamp)
                TimeStamp = AvValue;
        }
	}
    return {ServerChallenge: ServerChallenge, 
    	NegotiateFlags: NegotiateFlags};
}

function create_NTLM_AUTHENTICATE_MESSAGE(nonce, user, workstation, domain, password, NegotiateFlags) {
    var is_unicode  = NegotiateFlags & NTLM_NegotiateUnicode;
    var is_NegotiateExtendedSecurity = NegotiateFlags & NTLM_NegotiateExtendedSecurity;
    
    var flags = new Buffer(4);
    flags.writeUInt32LE(NTLM_TYPE2_FLAGS, 0);

    var BODY_LENGTH = 72;
    var Payload_start = BODY_LENGTH; // in bytes

    var Workstation = workstation.toUpperCase();
    var DomainName = domain.toUpperCase();
    var UserName = user;
    var EncryptedRandomSessionKey = "";
    if (is_unicode) {
        Workstation = new Buffer(Workstation, 'utf16le');
        DomainName = new Buffer(DomainName, 'utf16le');
        UserName = new Buffer(UserName, 'utf16le');
        EncryptedRandomSessionKey = new Buffer(0);
    }
    
    var lmh = new Buffer(21);
	lmhashbuf(password).copy(lmh);
	lmh.fill(0x00, 16); // null pad to 21 bytes
	var nth = new Buffer(21);
	nthashbuf(password).copy(nth);
	nth.fill(0x00, 16); // null pad to 21 bytes

	var LmChallengeResponse = makeResponse(lmh, nonce);
	var NtChallengeResponse = makeResponse(nth, nonce);
    
    if (is_NegotiateExtendedSecurity) {
    	var pwhash = new Buffer(21);
    	nthashbuf(password).copy(pwhash);
    	pwhash.fill(0x00, 16); // null pad to 21 bytes
    	
    	var ClientChallenge;
    	try {
    		ClientChallenge = crypto.randomBytes(8);
    	} catch (ex) {
    		ClientChallenge = new Buffer("00000000");
    	}
        
        NtChallengeResponse = ntlm2sr_calc_resp(pwhash, nonce, ClientChallenge);
        
        LmChallengeResponse = new Buffer(24);
        ClientChallenge.copy(LmChallengeResponse);
        LmChallengeResponse.fill(0x00, 8);
    }
    
    var DomainNameLength = DomainName.length;
	var UserNameLength = UserName.length;
	var WorkstationLength = Workstation.length;

	var pos = Payload_start;
	
	var Signature = new Buffer('NTLMSSP\0');
	var MessageType = new Buffer(4);
	MessageType.writeUInt32LE(3, 0);
	
	// Domain Name
	var DomainNameLen = new Buffer(2);
	DomainNameLen.writeUInt16LE(DomainNameLength, 0);
	var DomainNameOffset = new Buffer(4);
	DomainNameOffset.writeUInt32LE(pos, 0);
	pos += DomainNameLength;

	// Username
	var UserNameLen = new Buffer(2);
	UserNameLen.writeUInt16LE(UserNameLength, 0);
	var UserNameOffset = new Buffer(4);
	UserNameOffset.writeUInt32LE(pos, 0);
	pos += UserNameLength;
	
	// Workstation
	var WorkstationLen = new Buffer(2);
	WorkstationLen.writeUInt16LE(WorkstationLength, 0);
	var WorkstationOffset = new Buffer(4);
	WorkstationOffset.writeUInt32LE(pos, 0);
	pos += WorkstationLength;
    
	// Additional parameters
	var LmChallengeResponseLength = LmChallengeResponse.length;
	var NtChallengeResponseLength = NtChallengeResponse.length;
	var EncryptedRandomSessionKeyLength = EncryptedRandomSessionKey.length;
	
	// LM Challenge Response
	var LmChallengeResponseLen = new Buffer(2);
	LmChallengeResponseLen.writeUInt16LE(LmChallengeResponseLength, 0);
	var LmChallengeResponseOffset = new Buffer(4);
	LmChallengeResponseOffset.writeUInt32LE(pos, 0);
	pos += LmChallengeResponseLength;
	
	// NT Challenge Response
	var NtChallengeResponseLen = new Buffer(2);
	NtChallengeResponseLen.writeUInt16LE(NtChallengeResponseLength, 0);
	var NtChallengeResponseOffset = new Buffer(4);
	NtChallengeResponseOffset.writeUInt32LE(pos, 0);
	pos += NtChallengeResponseLength;
	
	// Encrypted Random Session Key
	var EncryptedRandomSessionKeyLen = new Buffer(2);
	EncryptedRandomSessionKeyLen.writeUInt16LE(EncryptedRandomSessionKeyLength, 0);
	var EncryptedRandomSessionKeyOffset = new Buffer(4);
	EncryptedRandomSessionKeyOffset.writeUInt32LE(pos, 0);
	pos += EncryptedRandomSessionKeyLength;
	
    var NegotiateFlags = flags;
    
    var versionFlags = new Buffer(8);
    var versionPos = 0;
    versionFlags.writeUInt8(5, versionPos); // Product Major Version
    versionPos++;
    versionFlags.writeUInt8(1, versionPos); // Product Minor Version
    versionPos++;
    versionFlags.writeUInt16LE(2600, versionPos); // Product Build
    versionPos += 2;
    versionFlags.writeUInt8(0, versionPos); // Version Reserved
    versionPos++;
    versionFlags.writeUInt8(0, versionPos); // Version Reserved 2
    versionPos++;
    versionFlags.writeUInt8(0, versionPos); // Version Reserved 3
    versionPos++;
    versionFlags.writeUInt8(15, versionPos); // NTLM Revision Current
    
    var MIC = new Buffer(16);
    MIC.fill(0x00, 16);
    
    var msg3 = Buffer.concat([Signature, MessageType, 
            LmChallengeResponseLen, LmChallengeResponseLen, LmChallengeResponseOffset, 
            NtChallengeResponseLen, NtChallengeResponseLen, NtChallengeResponseOffset, 
            DomainNameLen, DomainNameLen, DomainNameOffset, 
            UserNameLen, UserNameLen, UserNameOffset, 
            WorkstationLen, WorkstationLen, WorkstationOffset, 
            EncryptedRandomSessionKeyLen, EncryptedRandomSessionKeyLen, EncryptedRandomSessionKeyOffset, 
            NegotiateFlags, 
            versionFlags]);
    
    var Payload = Buffer.concat([DomainName, UserName, Workstation, LmChallengeResponse, 
                                 NtChallengeResponse, EncryptedRandomSessionKey]);
    
    msg3 = Buffer.concat([msg3, Payload]);
    
    msg3 = msg3.toString('base64');
    msg3 = msg3.replace('\n', '');
    
    return msg3;
}
    
function makeResponse(hash, nonce) {
	var out = new Buffer(24);
	for ( var i = 0; i < 3; i++) {
		var keybuf = $.oddpar($.expandkey(hash.slice(i * 7, i * 7 + 7)));
		var des = crypto.createCipheriv('DES-ECB', keybuf, '');
		var str = des.update(nonce, 'binary', 'binary');
		out.write(str, i * 8, i * 8 + 8, 'binary');
	}
	return out;
}

function ntlm2sr_calc_resp(pass, nonce, challenge) {
	
	// nonce, challenge -> ntlm2 session hash
	var session_nonce = Buffer.concat([nonce, challenge]);
	var session_nonce_md5 = crypto.createHash('md5').update(session_nonce).digest('hex');
	var ntlm2_session_hash = new Buffer(session_nonce_md5, 'hex');
	ntlm2_session_hash = ntlm2_session_hash.slice(0, 8);
	
	return makeResponse(pass, ntlm2_session_hash);
}

module.exports.create_NTLM_AUTHENTICATE_MESSAGE = create_NTLM_AUTHENTICATE_MESSAGE;
module.exports.parse_NTLM_CHALLENGE_MESSAGE = parse_NTLM_CHALLENGE_MESSAGE;
#!/usr/bin/tclsh8.5
#
# Yubikey-compatible validation server for OTP validation
#     Copyright (C) 2011 - Ben Fuhrmannek <bef@pentaphase.de>
# 
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, version 3 of the License.
# 
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
# 
#     You should have received a copy of the GNU General Public License
#     along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

## find/read configuration
package require fileutil
foreach etc [list /etc/yubi /opt/yubi/etc /opt/yubi-tcl/etc /usr/lib/yubi-tcl/etc /usr/local/lib/yubi-tcl/etc \
		[file join [file dirname [info script]] etc]] {
	if {[file isfile [file join $etc yubiconfig.tcl]]} {
		eval [::fileutil::cat -- [file join $etc yubiconfig.tcl]]
		break
	}
}
set auto_path [linsert $auto_path 0 [file join [file dirname [info script]]] {*}$::config(auto_path)]

##
package require yubi
if {$::argv == "test"} {
	package require yubi::wsapi::backend_dummy
} else {
	package require yubi::wsapi::backend_${::config(wsapi_backend)}
}
package require ncgi

## cgi
::ncgi::parse
::ncgi::header {text/plain}
fconfigure stdout -translation crlf


proc go {} {
	## check for required parameters
	set required_parameters {id otp}
	if {[::ncgi::value v11compatible] != "1"} {lappend required_parameters nonce}
	foreach {param} $required_parameters {
		if {[::ncgi::value $param] == ""} {
			return -code error -errorcode OTP -options {api_response MISSING_PARAMETER} "missing parameter: $param"
		}
	}
	
	## parameter validation
	array set params {}
	foreach {param} {id otp h timestamp nonce sl timeout ext v11compatible} {
		set params($param) [string trim [::ncgi::value $param ""]]
	}

	foreach param {timestamp ext v11compatible} {
		if {![info exists params($param)]} {set params($param) 0}
	}

	if {$params(v11compatible) == "1"} {
		set params(nonce) {0000000000000000}
		set params(sl) 100
	}

	if {![string is integer -strict $params(id)]} {
		return -code error -errorcode OTP -options {api_response MISSING_PARAMETER} "id is not an integer"
	}

	# if {[string trim $params(otp)] == ""} {
	# 	return -code error -errorcode OTP -options {api_response BAD_OTP} "empty OTP"
	# }
	
	if {[string length $params(nonce)] < 16 || [string length $params(nonce)] > 40 || ![string is xdigit $params(nonce)]} {
		return -code error -errorcode OTP -options {api_response MISSING_PARAMETER} "invalid nonce"
	}

	
	## get user data
	if {[set user [${::yubi::wsapi::backend}::get_user $params(id)]] == ""} {
		return -code error -errorcode OTP -options {api_response NO_SUCH_CLIENT} "no user found for id $params(id)"
	}

	## check key's active flag
	if {![dict get $user active]} {
		return -code error -errorcode OTP -options [list api_response OPERATION_NOT_ALLOWED] "user deactivated: id $params(id)"
	}

	## validate hmac if given or forced by peer configuration
	if {$params(h) != "" || [dict get $user force_hmac]} {
		set params_without_h [dict remove [::ncgi::nvlist] h]
		set hmac [::yubi::api_hmac [dict get $user apikey] $params_without_h]
		if {[string compare $hmac $params(h)] != 0} {
			return -code error -errorcode OTP -options {api_response BAD_SIGNATURE} "incorrect hmac"
		}
	}
	
	## normalize otp
	set otp [::yubi::normalize_modhex $params(otp)]
	
	## add otp/nonce to return data
	set ret [list \
		nonce $params(nonce) \
		otp $params(otp)]

	## check token id
	set tokenid [::yubi::tokenid $otp]
	if {$tokenid == ""} {
		return -code error -errorcode OTP -options [list api_response BAD_OTP data $ret] "token ID missing"
	}
	
	## get key data
	set key [::${::yubi::wsapi::backend}::get_key $tokenid]
	if {$key == {}} {
		return -code error -errorcode OTP -options [list api_response OPERATION_NOT_ALLOWED data $ret] "invalid key"
	}
	
	## add apikey to return data for message authentication
	lappend ret apikey [dict get $user apikey]
	
	## check key's active flag
	if {![dict get $key active]} {
		return -code error -errorcode OTP -options [list api_response OPERATION_NOT_ALLOWED data $ret] "key deactivated"
	}
	
	## decode otp (otpdecode checks for valid crc)
	set otpdata [::yubi::otpdecode [dict get $key aeskey] $otp]
	
	## verify secret uid
	if {[string compare [dict get $otpdata uid] [dict get $key uid]] != 0} {
		return -code error -errorcode OTP -options [list api_response BAD_OTP data $ret] "incorrect secret uid"
	}
	
	## check & update otp/nonce (with normalized otp)
	if {![${::yubi::wsapi::backend}::check_and_update_otp_nonce $params(id) $otp $params(nonce)]} {
		set api_response REPLAYED_REQUEST
		if {$params(v11compatible) == "1"} {set api_response REPLAYED_OTP}
		return -code error -errorcode OTP -options [list api_response $api_response data $ret] "go away."
	}
	
	## check counters
	set otpdata_ctr [dict get $otpdata ctr]
	set key_ctr [dict get $key ctr]
	set otpdata_use [dict get $otpdata use]
	set key_use [dict get $key use]

	if {$otpdata_ctr == $key_ctr && $otpdata_use <= $key_use || $otpdata_ctr < $key_ctr} {
		return -code error -errorcode OTP -options [list api_response REPLAYED_OTP data $ret] "counter deviation"
	}
	
	## update counters
	${::yubi::wsapi::backend}::update_counters $tokenid $otpdata_ctr $otpdata_use
	
	# prepare response
	lappend ret \
		status OK \
		sl 100
	
	## get more output for boolean parameters 'ext' and 'timestamp'
	if {$params(ext) == "1"} {
		lappend ret \
			usotp $otp \
			tokenid $tokenid
	}
	if {$params(timestamp) == "1"} {
		lappend ret timestamp [dict get $otpdata tstp] \
		sessioncounter $otpdata_ctr \
		sessionuse $otpdata_use
	}

	return $ret
}


## execute verification process w/ error handling
array set response {}
if {[catch {
	array set response [go]
} result opts]} {
	if {$::errorCode == "OTP"} {
		if {[dict exists $opts data]} {
			array set response [dict get $opts data]
		}
		set response(status) [dict get $opts api_response]
		set response(errormsg) $result
	} else {
		set response(status) BACKEND_ERROR
		if {$::config(debug)} {set response(debugmsg) $::errorInfo}
		puts stderr $::errorInfo
	}
}

## set t / timestamp
set response(t) [::yubi::timestamp]

## prepare response
set responsevalues {}
set responsekeys {t status timestamp sessioncounter sessionuse sl otp nonce}
if {[::ncgi::value ext ""] == "1" || $::argv == "test"} {lappend responsekeys errormsg usotp debugmsg}
foreach {param} $responsekeys {
	if {[info exists response($param)]} {
		lappend responsevalues $param $response($param)
	}
}

## add HMAC
if {[info exists response(apikey)]} {
	lappend responsevalues h [::yubi::api_hmac $response(apikey) $responsevalues]
}

## ykclient compatibility mode -- print "status=" as last element
## (http://code.google.com/p/yubico-c-client)
if {[dict exists $responsevalues status]} {
	set status [dict get $responsevalues status]
	set responsevalues [dict remove $responsevalues status]
	lappend responsevalues status $status
}

## print response
foreach {k v} $responsevalues {
	puts "$k=$v"
	if {$::config(debug)} {puts stderr "$k=$v"}
}

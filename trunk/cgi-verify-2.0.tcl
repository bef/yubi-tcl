#!/usr/bin/tclsh
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
set auto_path [linsert $auto_path 0 {*}$::config(auto_path)]

##
package require yubi
package require yubi::wsapi::backend_${::config(wsapi_backend)}
package require ncgi

## cgi
::ncgi::parse
::ncgi::header {text/plain}


proc go {} {
	## check for required parameters
	foreach {param} {id otp nonce} {
		if {[::ncgi::value $param] == ""} {
			return -code error -errorcode OTP -options {api_response MISSING_PARAMETER} "missing parameter: $param"
		}
	}
	
	## parameter validation
	array set params {}
	foreach {param} {id otp h timestamp nonce sl timeout} {
		set params($param) [string trim [::ncgi::value $param ""]]
	}

	if {![string is integer -strict $params(id)]} {
		return -code error -errorcode OTP -options {api_response MISSING_PARAMETER} "id is not an integer"
	}

	if {[string trim $params(otp)] == ""} {
		return -code error -errorcode OTP -options {api_response BAD_OTP} "empty OTP"
	}
	
	if {[string length $params(nonce)] < 16 || [string length $params(nonce)] > 40 || ![string is xdigit $params(nonce)]} {
		return -code error -errorcode OTP -options {api_response MISSING_PARAMETER} "invalid nonce"
	}

	if {![info exists params(timestamp)]} {set params(timestamp) 0}

	## get user data
	if {[set user [${::yubi::wsapi::backend}::get_user $params(id)]] == ""} {
		return -code error -errorcode OTP -options {api_response NO_SUCH_CLIENT} "no user found for id $params(id)"
	}

	## validate hmac if given or forced by peer configuration
	if {$params(h) != "" || [dict get $user force_hmac]} {
		set params_without_h [dict remove [::ncgi::nvlist] h]
		set hmac [::yubi::api_hmac [dict get $user apikey] $params_without_h]
		if {[string compare $hmac $params(h)] != 0} {
			return -code error -errorcode OTP -options {api_response BAD_SIGNATURE} "incorrect hmac"
		}
	}
	
	## check active flag
	if {![dict get $user active]} {
		return -code error -errorcode OTP -options {api_response OPERATION_NOT_ALLOWED} "key deactivated"
	}
	
	## decode otp (mhdecode checks for valid crc)
	set data [::yubi::mhdecode [dict get $user aeskey] $params(otp)]
	
	## verify secret uid
	if {[string compare [dict get $data uid] [dict get $user private_identity]] != 0} {
		return -code error -errorcode OTP -options {api_response BAD_OTP} "incorrect secret uid"
	}
	
	## check & update otp/nonce (with normalized otp=usotp)
	if {![${::yubi::wsapi::backend}::check_and_update_otp_nonce $params(id) [dict get $data usotp] $params(nonce)]} {
		return -code error -errorcode OTP -options {api_response REPLAYED_REQUEST} "go away."
	}
	
	## check counters
	set data_ctr [dict get $data ctr]
	set user_ctr [dict get $user ctr]
	set data_use [dict get $data use]
	set user_use [dict get $user use]

	if {$data_ctr == $user_ctr && $data_use <= $user_use || $data_ctr < $user_ctr} {
		return -code error -errorcode OTP -options {api_response REPLAYED_REQUEST} "counter deviation"
	}
	
	## update counters
	${::yubi::wsapi::backend}::update_counters [dict get $user keyid] $data_ctr $data_use
	
	# prepare response
	set ret [list apikey [dict get $user apikey] \
		status OK \
		sl 100 \
		nonce $params(nonce) \
		otp $params(otp) \
		usotp [dict get $data usotp] \
		]
	if {$params(timestamp) == "1"} {
		lappend ret timestamp [dict get $data tstp] \
		sessioncounter $data_ctr \
		sessionuse $data_use
	}

	return $ret
}


## execute verification process w/ error handling
array set response {}
if {[catch {
	array set response [go]
} result opts]} {
	if {$::errorCode == "OTP"} {
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
foreach {param} {t status timestamp sessioncounter sessionuse sl otp nonce errormsg usotp debugmsg} {
	if {[info exists response($param)]} {
		lappend responsevalues $param $response($param)
	}
}


## add HMAC
if {[info exists response(apikey)]} {
	lappend responsevalues h [::yubi::api_hmac $response(apikey) $responsevalues]
}

## print response
foreach {k v} $responsevalues {
	puts "$k=$v"
}

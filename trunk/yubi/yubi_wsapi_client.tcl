#
# web-service API client library
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

package require http

namespace eval ::yubi::wsapi::client {
	variable version 0.1
	variable last_request {}
	variable last_response {}

	## parse "key=value" lines
	proc parse_response {body} {
		set data {}
		foreach line [split $body "\r\n"] {
			set sep_index [string first = $line]
			if {$sep_index < 0} {continue}
			set k [string range $line 0 $sep_index-1]
			set v [string range $line $sep_index+1 end]
			lappend data $k $v
		}
		return $data
	}
	
	proc check {otp api_id api_key {api_url "http://api.yubico.com/wsapi/2.0/verify"} {extra_args {}}} {
		variable last_request {}
		variable last_response {}
		set in [string tolower [string trim $otp]]
		
		## query api
		set nonce [::yubi::nonce]
		set querylist [list id $api_id otp $in nonce $nonce]
		lappend querylist {*}$extra_args
		set hmac [::yubi::api_hmac $api_key $querylist]
		lappend querylist h $hmac
		set last_request $querylist
		set query [::http::formatQuery {*}$querylist]
		set token [::http::geturl "${api_url}?$query" -method GET -keepalive 0]
		set http_response [::http::data $token]
		set http_code [::http::code $token]
		::http::cleanup $token

		## check http response code
		if {[lindex [split $http_code] 1] != "200"} {
			return -code error -errorcode WS "got HTTP $http_code from $api_url"
		}

		## parse response
		set data [parse_response $http_response]
		set last_response $data

		## validate
		if {![dict exists $data status] || [dict get $data status] != "OK"} {
			## non-OK status
			return [list -2 "non-OK status: [dict get $data status]"]
		}
		
		foreach k {t status otp nonce h} {
			if {![dict exists $data $k]} {
				## missing response key
				return [list -1 "missing response key $k"]
			}
		}

		if {[dict get $data otp] != $in || [dict get $data nonce] != $nonce} {
			## incorrect otp or nonce in response
			return [list -3 "incorrect otp or nonce in response"]
		}

		set hash [dict get $data h]
		set myhash [::yubi::api_hmac $api_key [dict remove $data h]]
		if {$hash != $myhash} {
			## incorrect hmac signature
			return [list -4 "incorrect hmac signature"]
		}

		set t [::yubi::scan_timestamp [dict get $data t]]
		if {$t == ""} {
			## ignore invalid timestamp
		} else {
			set t0 [clock seconds]
			## allow +- 2 hours
			if {$t > [expr {$t0 + 2*3600}] || $t < [expr {$t0 - 2*3600}]} {
				## timestamp off by at least 2 hours
				return [list -5 "timestamp off"]
			}
		}

		## success
		return 1
	}
	
}

package provide yubi::wsapi::client $::yubi::wsapi::client::version

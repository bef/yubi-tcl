#
# web-service API dummy backend
# -- sample values have been chosen to accommodate unit testing
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

namespace eval ::yubi::wsapi::backend_dummy {
	namespace import ::yubi::wsapi::*
	set ::yubi::wsapi::backend [namespace current]
	variable version 0.1

	
	## return api and yubikey data for given api-id
	proc get_user {id} {
		if {$id != 1} {return}
		return [list \
			apikey da5d1a9407db6df1b547c0daefb6298a \
			service_description {fnord secure email provider} \
			force_hmac 1 \
			]
	}
	
	proc get_key {tokenid} {
		set active 1
		switch -- $tokenid {
			cccctultnuuv {set active 0}
			beeitultnuuv {}
			default {return}
		}
		return [list \
			aeskey a75bab9004c818850b0b549e32c4491c \
			uid 000000000bef \
			ctr 3 \
			use 5 \
			active $active \
			usertoken {foo@example.com} \
			]
	}
	
	## detect replayed otp/nonce -> return 0
	## otherwise update and return 1 on success
	proc check_and_update_otp_nonce {tokenid otp nonce} {
		if {"${otp}|${nonce}" == "beeitultnuuvjvcbctrjlihedubldkeiuehrgcblhhlf|0000000000000001"} {return 0}
		return 1
	}
	
}

package provide yubi::wsapi::backend_dummy $::yubi::wsapi::backend_dummy::version
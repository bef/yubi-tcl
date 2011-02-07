#
# web-service API backend template
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

namespace eval ::yubi::wsapi {
	## current backend namespace
	## -- change this to activate a backend
	variable backend [namespace current]
	
	## defaults for optional user data fields
	## -- use this as a dict merge basis, e.g. dict merge $::yubi::wsapi::data_template {apikey 12345 ...}
	variable data_template {service_description "unknown service" force_hmac 0 active 1 usertoken "anonymous"}

	## user data fileds separated into mandatory and optional api user fields and yubikey fields
	## -- relation: 1-to-n: each key can be used by several api users
	## -- all fields must be returned by get_user as dict
	variable mandatory_user_fields {apikey keyid}
	variable optional_user_fields {service_description force_hmac}
	variable mandatory_key_fields {aeskey private_identity}
	variable optional_key_fields {active usertoken}
	variable all_fields [join [list $mandatory_user_fields $optional_user_fields $mandatory_key_fields $optional_key_fields]]
	
	## return api and yubikey data for given api-id
	proc get_user {id} {
		return
	}
	
	## detect replayed otp/nonce -> return 0
	## otherwise update and return 1 on success
	proc check_and_update_otp_nonce {id otp nonce} {
		return 1
	}
	
	## update global and session counters
	proc update_counters {keyid ctr use} {
	}
	
	## export everything
	namespace export {*}
}

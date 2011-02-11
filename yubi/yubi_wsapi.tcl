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
	
	## defaults for optional user and key data fields
	## -- use this as a dict merge basis, e.g. dict merge $::yubi::wsapi::data_template {apikey 12345 ...}
	variable data_template {service_description "unknown service" force_hmac 0}
	variable key_template {active 1 usertoken "anonymous" serialnr 0}

	## user data fileds separated into mandatory and optional api user fields and yubikey fields
	## -- relation: 1-to-n: each key can be used by several api users
	## -- all fields must be returned by get_user as dict
	variable mandatory_user_fields {apikey}
	variable optional_user_fields {service_description force_hmac}
	variable mandatory_key_fields {aeskey uid publicid}
	variable optional_key_fields {active usertoken serialnr}
	variable all_fields [join [list $mandatory_user_fields $optional_user_fields $mandatory_key_fields $optional_key_fields]]
	
	##
	## API interface
	##
	
	## return api data for given api-id
	proc get_user {id} {
		return
	}
	
	## return key data
	proc get_key {tokenid} {
		return
	}
	
	## detect replayed otp/nonce -> return 0
	## otherwise update and return 1 on success
	proc check_and_update_otp_nonce {tokenid otp nonce} {
		return 1
	}
	
	## update global and session counters
	proc update_counters {tokenid ctr use} {
	}
	
	
	##
	## key management interface
	##
	
	## return {id {k v ...}} user data
	proc get_users {ids} {}
	
	## return {id {k v ...}} key data
	proc get_keys {tokenids} {}
	
	## check if key exists
	proc key_exists {tokenid} {
		return 0
	}
	
	## store key
	proc store_key {tokenid data} {}

	## store user
	proc store_user {uid data} {}
	
	## propose new api user id
	proc get_new_userid {} {
		return ""
	}
	
	## export everything
	namespace export {*}
}

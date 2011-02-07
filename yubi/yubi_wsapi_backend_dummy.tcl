#
# web-service API dummy backend
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
			keyid 12345 \
			aeskey a75bab9004c818850b0b549e32c4491c \
			private_identity 000000000bef \
			ctr 0 \
			use 0 \
			active 1 \
			usertoken {foo@example.com} \
			]
	}
	
}

package provide yubi::wsapi::backend_dummy $::yubi::wsapi::backend_dummy::version
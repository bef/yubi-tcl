#
# web-service API file backend
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

package require md5

namespace eval ::yubi::wsapi::backend_file {
	namespace import ::yubi::wsapi::*
	set ::yubi::wsapi::backend [namespace current]
	variable version 0.1
	variable config
	array set config {datadir "/opt/yubi/data" cachedir "/var/cache/yubi"}
	if {[info exists ::config(wsapi_backend_file)]} {
		array set config $::config(wsapi_backend_file)
	}
	
	proc parse_datafile {fn} {
		set data {}
		set f [open $fn r]
		set linenr 0
		while {[gets $f line] >= 0} {
			incr linenr
			if {[regexp -- {^\s*#} $line]} {continue}
			if {[regexp -- {^\s*$} $line]} {continue}
			if {[regexp -- {^\s*(.*?)\s*=\s*(.*?)\s*$} $line all key value]} {
				lappend data $key $value
			} else {
				return -code error -errorcode WS "syntax error in '$fn' line $linenr"
			}
		}
		close $f
		return $data
	}
	
	proc check_data_keys {data mandatory_keys optional_keys filename} {
		set all_keys [join [list $mandatory_keys $optional_keys]]

		foreach key $mandatory_keys {
			if {![dict exists $data $key]} {
				# return -code error -errorcode WS "missing entry '$key' in '$filename'"
				puts stderr "missing entry '$key' in '$filename'"
				return 0
			}
		}
		
		foreach key [dict keys $data] {
			if {![lsearch -exact $all_keys $key] == -1} {
				# return -code error -errorcode WS "unknown entry '$key' in '$filename'"
				puts stderr "unknown entry '$key' in '$filename'"
				return 0
			}
		}
		
		return 1
	}
	
	proc get_counters {keyid} {
		variable config
		set counter_file [file join $config(cachedir) counters $keyid]
		if {![file isfile $counter_file]} {
			return {0 0}
		}
		
		set f [open $counter_file r]
		gets $f line
		close $f
		set line [string trim $line]
		if {![regexp -- {^\d+ \d+$} $line]} {
			return {0 0}
		}
		return $line
	}
	
	## API ##
	
	## return api and yubikey data for given api-id
	proc get_user {id} {
		variable config
		
		## get api user data
		set user_file [file join $config(datadir) users $id]
		
		if {![file isfile $user_file]} {return}
		set user_data [parse_datafile $user_file]
		if {![check_data_keys $user_data $::yubi::wsapi::mandatory_user_fields $::yubi::wsapi::optional_user_fields $user_file]} {
			return
		}
		
		if {[string length [dict get $user_data keyid]] == 0} {
			# return -code error -errorcode WS "no key associated with user in '$user_file'"
			puts stderr "no key associated with user in '$user_file'"
			return
		}
		
		## get yubikey data
		set key_file [file join $config(datadir) keys [dict get $user_data keyid]]
		if {![file isfile $key_file]} {
			# return -code error -errorcode WS "invalid key file '$key_file' for user id $id"
			puts stderr "invalid key file '$key_file' for user id $id"
			return
		}
		
		set key_data [parse_datafile $key_file]
		if {![check_data_keys $key_data $::yubi::wsapi::mandatory_key_fields $::yubi::wsapi::optional_key_fields $key_file]} {
			return
		}
		
		## get key's counters
		set counters [get_counters [dict get $user_data keyid]]
		set counters_data [list ctr [lindex $counters 0] use [lindex $counters 1]]
		
		## merge data
		set data [dict merge $::yubi::wsapi::data_template $user_data $key_data $counters_data]
		
		return $data
	}
	
	## detect replayed otp/nonce -> return 0
	## otherwise update and return 1 on success
	proc check_and_update_otp_nonce {id otp nonce} {
		variable config
		set cachedir [file join $config(cachedir) nonce $id]
		set hash [string tolower [::md5::md5 -hex "$otp:$nonce"]]
		set cachefile [file join $cachedir $hash]
		
		## file exists -> failure
		if {[file isfile $cachefile]} {return 0}
		
		## create cachedir
		if {![file isdirectory $cachedir]} {
			file mkdir $cachedir
		}
		
		## create cachefile
		set f [open $cachefile w]
		close $f
		
		## ok
		return 1
	}
	
	## update global and session counters
	proc update_counters {keyid ctr use} {
		variable config
		set counters_dir [file join $config(cachedir) counters]
		set counter_file [file join $counters_dir $keyid]
		if {![file isdirectory $counters_dir]} {
			file mkdir $counters_dir
		}
		set f [open $counter_file w]
		puts -nonewline $f "$ctr $use"
		close $f
	}
	
}

package provide yubi::wsapi::backend_file $::yubi::wsapi::backend_file::version
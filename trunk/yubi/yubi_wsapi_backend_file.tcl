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

package require yubi
package require md5

namespace eval ::yubi::wsapi::backend_file {
	namespace import ::yubi::wsapi::*
	set ::yubi::wsapi::backend [namespace current]
	variable version 0.1
	variable config
	
	## configuration
	array set config {datadir "/opt/yubi/data" cachedir "/var/cache/yubi" check_nonceotp_replay 0}
	if {[info exists ::config(wsapi_backend_file)]} {
		array set config $::config(wsapi_backend_file)
	}
	if {![info exists config(userdir)]} {set config(userdir) [file join $config(datadir) users]}
	if {![info exists config(keydir)]} {set config(keydir) [file join $config(datadir) keys]}
	if {![info exists config(counterdir)]} {set config(counterdir) [file join $config(cachedir) counters]}
	
	## helper functions

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
				puts stderr "missing entry '$key' in '$filename'"
				return 0
			}
		}
		
		foreach key [dict keys $data] {
			if {[lsearch -exact $all_keys $key] == -1} {
				puts stderr "unknown entry '$key' in '$filename'"
				return 0
			}
		}
		
		return 1
	}
	
	proc get_counters {tokenid} {
		variable config
		set counter_file [file join $config(counterdir) $tokenid]
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
	
	proc glob_filter {dir {pattern {}}} {
		if {[llength $pattern] == 0} {set pattern "*"}
		if {[catch {
			set files [glob -directory $dir {*}$pattern]
		} result opts]} {return}
		return $files
	}
	
	proc store_kv {fn data} {
		set f [open $fn w 0640]
		puts $f "## created/modified: [clock format [clock seconds] -format {%Y-%m-%d %H:%M:%S UTC} -timezone :UTC]"
		foreach {k v} $data {
			puts $f "$k = $v"
		}
		close $f
	}
	
	
	##
	## API interface
	##
	
	## return api data for given api-id
	proc get_user {id} {
		variable config
		
		## get api user data
		set user_file [file join $config(userdir) $id]
		
		if {![file isfile $user_file]} {return}
		set user_data [parse_datafile $user_file]
		if {![check_data_keys $user_data $::yubi::wsapi::mandatory_user_fields $::yubi::wsapi::optional_user_fields $user_file]} {
			return
		}
		
		return [dict merge $::yubi::wsapi::user_template $user_data]
	}
	
	## return key data
	proc get_key {tokenid {with_counters 1}} {
		variable config
		set key_file [file join $config(keydir) $tokenid]
		if {![file isfile $key_file]} {
			puts stderr "invalid key file '$key_file'"
			return
		}
		
		set key_data [parse_datafile $key_file]
		if {![check_data_keys $key_data $::yubi::wsapi::mandatory_key_fields $::yubi::wsapi::optional_key_fields $key_file]} {
			return
		}
		
		if {$with_counters} {
			## get key's counters
			set counters [get_counters $tokenid]
			set counters_data [list ctr [lindex $counters 0] use [lindex $counters 1]]
		
			## merge data
			set key_data [dict merge $::yubi::wsapi::key_template $key_data $counters_data]
		}
		
		return $key_data
	}
	
	## detect replayed otp/nonce -> return 0
	## otherwise update and return 1 on success
	proc check_and_update_otp_nonce {tokenid otp nonce} {
		variable config
		if {!$config(check_nonceotp_replay)} { return 1 }
		
		set cachedir [file join $config(cachedir) nonce $tokenid]
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
		set counter_file [file join $config(counterdir) $keyid]
		if {![file isdirectory $config(counterdir)]} {
			file mkdir $config(counterdir)
		}
		set f [open $counter_file w]
		puts -nonewline $f "$ctr $use"
		close $f
	}
	
	##
	## key management interface
	##
	
	## return {id {k v ...}} user data
	proc get_users {ids} {
		variable config
		set ret {}
		foreach fn [glob_filter $config(userdir) $ids] {
			set id [lindex [file split $fn] end]
			lappend ret $id [get_user $id]
		}
		return $ret
	}
	
	## return {id {k v ...}} key data
	proc get_keys {tokenids} {
		variable config
		set ret {}
		foreach fn [glob_filter $config(keydir) $tokenids] {
			set id [lindex [file split $fn] end]
			lappend ret $id [get_key $id 0]
		}
		return $ret
	}
	
	## check if key exists
	proc key_exists {tokenid} {
		variable config
		set keyfile [file join $config(keydir) $tokenid]
		return [file exists $keyfile]
	}
	
	## check if user exists
	proc user_exists {uid} {
		variable config
		set userfile [file join $config(userdir) $uid]
		return [file exists $userfile]
	}

	## store key
	proc store_key {tokenid data} {
		variable config
		set keyfile [file join $config(keydir) $tokenid]
		store_kv $keyfile $data
	}
	
	## store user
	proc store_user {uid data} {
		variable config
		set userfile [file join $config(userdir) $uid]
		store_kv $userfile $data
	}
	
	## propose new api user id
	proc get_new_userid {} {
		variable config
		set uid 0
		if {[set files [glob_filter $config(userdir) "*"]] != ""} {
			foreach fn $files {
				set fn [lindex [file split $fn] end]
				if {![string is digit $fn]} {continue}
				if {$fn >= $uid} {set uid [expr {$fn + 1}]}
			}
		}
		return $uid
	}	
	
	## delete user
	proc delete_user {uid} {
		variable config
		set userfile [file join $config(userdir) $uid]
		if {[file exists $userfile]} {
			file delete -- $userfile
		}
	}
	
	## delete key, counters and nonce cache
	proc delete_key {tokenid} {
		variable config
		set keyfile [file join $config(keydir) $tokenid]
		if {[file exists $keyfile]} {
			file delete -- $keyfile
		}
		
		set counter_file [file join $config(counterdir) $tokenid]
		if {[file exists $counter_file]} {
			file delete -- $counter_file
		}
		
		set cachedir [file join $config(cachedir) nonce $tokenid]
		if {[file exists $cachedir]} {
			file delete -force -- $cachedir
		}
		
	}
	
}

package provide yubi::wsapi::backend_file $::yubi::wsapi::backend_file::version
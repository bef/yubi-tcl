#!/usr/bin/tclsh
#
# key management tool for web-service API file backend
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
		[file join [file dirname [info script]] .. etc]] {
	if {[file isfile [file join $etc yubiconfig.tcl]]} {
		eval [::fileutil::cat -- [file join $etc yubiconfig.tcl]]
		break
	}
}
set auto_path [linsert $auto_path 0 {*}$::config(auto_path)]
set auto_path [linsert $auto_path 0 [file join [file dirname $::argv0] ..]]
package require yubi
package require yubi::wsapi::backend_file

##
set datadir [dict get $::config(wsapi_backend_file) datadir]
set keydir [file join $datadir keys]
set userdir [file join $datadir users]
##


## command registry
set cmds {}
proc cmd {cmd help body} {lappend ::cmds $cmd $help $body}

proc match {cmd input} {
	set input [lrange $input 0 "[llength $cmd]-1"]
	for {set i 0} {$i < [llength $cmd]} {incr i} {
		if {![string match [lindex $cmd $i] [lindex $input $i]]} {return 0}
	}
	return 1
}

proc call {input} {
	foreach {cmd help body} $::cmds {
		if {[match $cmd $input]} {
			set args [lrange $input [llength $cmd] end]
			return [eval $body]
		}
	}
	puts "unknown command"
	# return -code error -errorcode {NOT_FOUND}
}

proc print_help {} {
	puts "== COMMANDS =="
	foreach {cmd help body} $::cmds {
		puts "$help"
	}
	puts ""
	puts "NOTE: commands can be abbreviated. e.g. 'l k' for 'list keys'"
	puts ""
}
cmd {h*} {help} {print_help}

## command implementation helper functions

proc glob_filter {dir pattern} {
	if {[llength $pattern] == 0} {set pattern "*"}
	if {[catch {
		set files [glob -directory $dir {*}$pattern]
	} result opts]} {return}
	return $files
}

proc print_kv {data {headline {}} {indent {  }}} {
	if {$headline != ""} {puts $headline}
	foreach {k v} $data {
		puts [format "%s%-20s %s" $indent $k $v]
	}
}

proc read_yn {text {default y}} {
	while {1} {
		puts -nonewline "$text (y/n) \[$default\] "
		flush stdout
		if {[gets stdin input] < 0} {return -code error "EOF"}
		set input [string trim [string tolower $input]]
		switch -- $input {
			y -
			n {return $input}
			{} {return $default}
			default {continue}
		}
	}
}

proc read_text {text {default ""}} {
	puts -nonewline "$text \[$default\] "
	flush stdout
	if {[gets stdin input] < 0} {return -code error "EOF"}
	set input [string trim $input]
	if {$input == ""} {set input $default}
	return $input
}

proc store_kv {fn data} {
	set f [open $fn w]
	puts $f "## created/modified: [clock format [clock seconds] -format {%Y-%m-%d %H:%M:%S UTC} -timezone :UTC]"
	foreach {k v} $data {
		puts $f "$k = $v"
	}
	close $f
}

## commands

cmd {l* u*} {list users [pattern]} {
	if {[set files [glob_filter $::userdir $args]] == ""} {
		puts "empty."
		return
	}

	foreach fn $files {
		set user_data [::yubi::wsapi::backend_file::parse_datafile $fn]
		print_kv $user_data "====\[ user [lindex [file split $fn] end] \]===="

		if {![dict exists $user_data keyid]} {continue}
		set keyfile [file join $::keydir [dict get $user_data keyid]]
		if {![file isfile $keyfile]} {
			puts "  ** WARNING ** invalid keyfile: $keyfile"
			continue
		}

		set key_data [::yubi::wsapi::backend_file::parse_datafile $keyfile]
		print_kv $key_data "  == key [lindex [file split $keyfile] end]:" "    "
	}
}

cmd {l* k*} {list keys [pattern]} {
	if {[set files [glob_filter $::keydir $args]] == ""} {
		puts "empty."
		return
	}

	foreach fn $files {
		set key_data [::yubi::wsapi::backend_file::parse_datafile $fn]
		print_kv $key_data "====\[ user [lindex [file split $fn] end] \]===="
	}
}

proc yubikey_export {data} {
	set cmd [format "ykpersonalize -a%s -osend-ref -ouid=%s" [dict get $data aeskey] [dict get $data private_identity]]
	puts "The following command will be executed:\n  $cmd"
	set cmdaddon [read_text "additional arguments?" ""]
	set cmd "$cmd $cmdaddon"
	if {[catch {exec {*}$cmd} result opts]} {
		puts "error: $result"
	}
}

proc new_key {} {
	## get key id
	set keyid [read_text "key id?"]
	if {$keyid == "" || ![string is digit $keyid]} {
		puts ":( invalid key id"
		return
	}
	set keyfile [file join $::keydir $keyid]
	if {[file exists $keyfile]} {
		puts ":( key already exists"
		return
	}
	
	## get aeskey
	set aeskey [read_text "new AES key or confirm?" [::yubi::nonce]]
	if {![string is xdigit $aeskey] || [string length $aeskey] < 32} {
		puts ":( invalid aeskey"
		return
	}
	
	## get private identity (12 bytes; to be encrypted)
	set private_identity [read_text "private identity?" [string range [::yubi::nonce] 0 11]]
	if {![string is xdigit $private_identity] || [string length $private_identity] != 12} {
		puts ":( invalid private identity"
		return
	}
	
	## get usertoken - any name or email associated with the key owner
	set usertoken [read_text "usertoken?" "foo@example.com"]
	
	## merge data
	set key_data [list aeskey $aeskey private_identity $private_identity active 1 usertoken $usertoken]

	## confirm
	print_kv $key_data "====\[ new key $keyid \]===="
	if {[read_yn "Commit?" y] != "y"} {return}
	
	## create file
	store_kv $keyfile $key_data

	if {[read_yn "Write key data to physical device?"] == "y"} {
		yubikey_export $key_data
	}

	return [list keyid $keyid data $key_data]
}
cmd {n* k*} {new key} {return [new_key]}

cmd {n* u*} {new user} {
	## find new user id
	set uid 0
	if {[set files [glob_filter $::userdir "*"]] != ""} {
		foreach fn $files {
			set fn [lindex [file split $fn] end]
			if {![string is digit $fn]} {continue}
			if {$fn >= $uid} {set uid [expr {$fn + 1}]}
		}
	}
	
	## get uid
	set uid [read_text "new API user id?" $uid]
	if {$uid == "" || ![string is digit $uid]} {
		puts ":( invalid key id"
		return
	}
	set userfile [file join $::userdir $uid]
	if {[file exists $userfile]} {
		puts ":( user already exists"
		return
	}
	
	## get apikey
	set apikey [read_text "new AES API key?" [::yubi::nonce]]
	if {![string is xdigit $apikey] || [string length $apikey] != 32} {
		puts ":( invalid apikey"
		return
	}

	## get service description
	set service_description [read_text "service description" "www.example.com"]
	
	## get force hmac flag
	set force_hmac [read_yn "force HMAC?" "y"]
	set force_hmac [expr {$force_hmac == "y"}]
	
	## get key id
	set keyid [read_text "key id?" "new"]
	if {$keyid == "new"} {
		## generate new key
		puts "====\[ generating new key \]===="
		set key_data [new_key]
		if {$key_data == ""} {
			puts ":( no key"
			return
		}
		set keyid [dict get $key_data keyid]
		set key_data [dict get $key_data data]
	} else {
		## use existing key
		if {$keyid == "" || ![string is digit $keyid]} {
			puts ":( invalid key id"
			return
		}
		set keyfile [file join $::keydir $keyid]
		if {![file exists $keyfile]} {
			puts ":( key does not exist"
			return
		}
		set key_data [::yubi::wsapi::backend_file::parse_datafile $keyfile]
	}
	
	set user_data [list apikey $apikey service_description $service_description force_hmac $force_hmac keyid $keyid]
	print_kv $user_data "====\[ new user $uid \]===="
	print_kv $key_data "  ==\[ associated key $keyid \]=="
	
	if {[read_yn "Commit?" y] != "y"} {return}
	
	## create file
	store_kv $userfile $user_data
	
	return [list uid $uid data $user_data]
}

cmd {e* k*} {export key <id>} {
	set keyid [string trim $args]
	if {$keyid == "" || ![string is digit $keyid]} {
		puts ":( no id"
		return
	}
	set keyfile [file join $::keydir $keyid]
	if {![file exists $keyfile]} {
		puts ":( key does not exist"
		return
	}
	set key_data [::yubi::wsapi::backend_file::parse_datafile $keyfile]
	yubikey_export $key_data
}


## interactive mode
proc read_loop {} {
	while {1} {
		puts -nonewline "> "
		flush stdout
		if {[gets stdin input] < 0} {return}
		set input [string trim $input]
		if {$input == ""} {continue}
		call $input
	}
}

if {$::argc > 0} {
	call [string trim $::argv]
} else {
	read_loop
}

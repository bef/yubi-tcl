#!/usr/bin/tclsh8.5
#
# key management tool for web-service API backend
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
package require yubi::wsapi::backend_${::config(wsapi_backend)}



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


proc print_kv {data {headline {}} {indent {  }}} {
	if {$headline != ""} {puts $headline}
	foreach {k v} $data {
		puts [format "%s%-20s %s" $indent $k $v]
	}
}

proc read_yn {text {default y}} {
	switch -- $default {
		y -
		1 {set default y}
		default {set default n}
	}
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


## commands

cmd {l* u*} {list users [id]} {
	set users [${::yubi::wsapi::backend}::get_users $args]
	if {$users == ""} {
		puts "empty."
		return
	}
	
	foreach {id user_data} $users {
		if {[dict exists $user_data apikey]} {
			lappend user_data {## apikey (BASE64)} [::yubi::hex2base64 [dict get $user_data apikey]]
		}
		print_kv $user_data "====\[ user $id \]===="
	}
}

cmd {l* k*} {list keys [pattern]} {
	set keys [${::yubi::wsapi::backend}::get_keys $args]
	if {$keys == ""} {
		puts "empty."
		return
	}
	
	foreach {id key_data} $keys {
		print_kv $key_data "====\[ key token id $id \]===="
	}
}

proc yubikey_export {data} {
	set cmd [format "ykpersonalize -a%s -ouid=%s" [dict get $data aeskey] [dict get $data uid]]
	if {[dict exists $data publicid] && [dict get $data publicid] != ""} {
		set cmd "$cmd -ofixed=h:[dict get $data publicid]"
	}
	if {[read_yn "Send reference encoding as first 16 bytes (SEND_REF)?" n] == "y"} {
		set cmd "$cmd -osend-ref"
	}
	puts "The following command will be executed:\n  $cmd"
	set cmdaddon [read_text "additional arguments?" ""]
	set cmd "$cmd $cmdaddon"
	if {[read_yn "Execute?" y] != "y"} {return}
	if {[catch {exec {*}$cmd} result opts]} {
		puts "error: $result"
	}
}

proc edit_key {tokenid data} {
	set public_identity [::yubi::modhex_decode $tokenid]
	puts "public identity: $public_identity"
	
	## get private identity (12 bytes; to be encrypted)
	set uid [read_text "private identity (uid)?" [dict get $data uid]]
	if {![string is xdigit $uid] || [string length $uid] != 12} {
		puts ":( invalid uid"
		return
	}
	
	## get aeskey
	set aeskey [read_text "AES key or confirm?" [dict get $data aeskey]]
	if {![string is xdigit $aeskey] || [string length $aeskey] < 32} {
		puts ":( invalid aeskey"
		return
	}
	
	## get serialnr
	set serialnr [read_text "yubikey serialnr (optional)?" [dict get $data serialnr]]
	if {![string is digit $serialnr] || [string length $serialnr] > 16} {
		puts ":( invalid serialnr"
		return
	}
	
	## get usertoken - any name or email associated with the key owner
	set usertoken [read_text "usertoken?" [dict get $data usertoken]]
	
	## active?
	set active [read_yn "enabled?" [dict get $data active]]
	set active [expr {$active == "y"}]

	## merge data
	set key_data [list \
		aeskey $aeskey \
		uid $uid \
		active $active \
		usertoken $usertoken \
		serialnr $serialnr \
		publicid $public_identity]

	## confirm
	print_kv $key_data "====\[ key $tokenid \]===="
	if {[read_yn "Commit?" y] != "y"} {return}

	## store key
	${::yubi::wsapi::backend}::store_key $tokenid $key_data

	if {[read_yn "Write key data to physical device?" n] == "y"} {
		yubikey_export $key_data
	}

	return [list tokenid $tokenid data $key_data]
}

cmd {n* k*} {new key} {
	## get token id - 0x28, 16-bit user id, 24-bit key id
	set tmp_public_identity "28[string range [::yubi::nonce] 0 9]"
	set tokenid [::yubi::modhex_encode $tmp_public_identity]

	set tokenid [read_text "token id ('-' = empty)?" $tokenid]
	if {$tokenid == "-"} {set tokenid ""}
	if {![::yubi::is_valid_modhex $tokenid] || [string length $tokenid] > 16} {
		puts ":( invalid tokenid"
		return
	}
	set public_identity [::yubi::modhex_decode $tokenid]
	
	## exists?
	if {[${::yubi::wsapi::backend}::key_exists $tokenid]} {
		puts ":( key exists already"
		return
	}

	set key_data [list \
		aeskey [::yubi::nonce] \
		uid [string range [::yubi::nonce] 0 11] \
		active 1 \
		usertoken "foo@example.com" \
		serialnr 0 \
		publicid $public_identity]

	return [edit_key $tokenid $key_data]
}

cmd {ed* k*} {edit key <id>} {
	set tokenid [string trim $args]
	if {$tokenid == "" || ![::yubi::is_valid_modhex $tokenid]} {
		puts ":( no id"
		return
	}
	set key_data [${::yubi::wsapi::backend}::get_key $tokenid 0]
	if {$key_data == ""} {
		puts ":( key does not exist"
		return
	}

	return [edit_key $tokenid $key_data]
}

cmd {ex* k*} {export key <id>} {
	set tokenid [string trim $args]
	if {$tokenid == "" || ![::yubi::is_valid_modhex $tokenid]} {
		puts ":( no id"
		return
	}
	set key_data [${::yubi::wsapi::backend}::get_key $tokenid 0]
	if {$key_data == ""} {
		puts ":( key does not exist"
		return
	}

	yubikey_export $key_data
}


proc edit_user {uid data} {
	## get apikey
	set apikey [read_text "AES API key?" [dict get $data apikey]]
	if {![string is xdigit $apikey] || [string length $apikey] != 32} {
		puts ":( invalid apikey"
		return
	}

	## get service description
	set service_description [read_text "service description" [dict get $data service_description]]
	
	## get force hmac flag
	set force_hmac [read_yn "force HMAC?" [dict get $data force_hmac]]
	set force_hmac [expr {$force_hmac == "y"}]

	## active?
	set active [read_yn "enabled?" [dict get $data active]]
	set active [expr {$active == "y"}]
	
	## merge data and confirm
	set user_data [list \
		apikey $apikey \
		service_description $service_description \
		force_hmac $force_hmac \
		active $active]
	print_kv $user_data "====\[ user $uid \]===="
	
	if {[read_yn "Commit?" y] != "y"} {return}
	
	## create user
	${::yubi::wsapi::backend}::store_user $uid $user_data
	
	return [list uid $uid data $user_data]
}

cmd {n* u*} {new user} {
	## get uid
	set uid [${::yubi::wsapi::backend}::get_new_userid]
	set uid [read_text "new API user id?" $uid]
	if {$uid == "" || ![string is digit $uid]} {
		puts ":( invalid key id"
		return
	}
	
	## exists?
	if {[${::yubi::wsapi::backend}::user_exists $uid]} {
		puts ":( user exists already"
		return
	}

	return [edit_user $uid [list \
		apikey [::yubi::nonce] \
		service_description "www.example.com" \
		force_hmac y \
		active y]]
}

cmd {e* u*} {edit user <uid>} {
	set uid [string trim $args]
	if {$uid == "" || ![string is digit $uid]} {
		puts ":( invalid uid"
	}
	set user_data [${::yubi::wsapi::backend}::get_user $uid]
	if {$user_data == ""} {
		puts ":( user does not exist"
		return
	}
	return [edit_user $uid $user_data]
}

cmd {s* l*} {show license} {
	package require http
	set token [http::geturl {http://www.gnu.org/licenses/gpl-3.0.txt}]
	puts [http::data $token]
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

puts "yubi key management tool  Copyright (C) 2011  Ben Fuhrmannek <bef@pentaphase.de>
|- yubilib version ${::yubi::version}
|- backend: '${::config(wsapi_backend)}' version [set ${::yubi::wsapi::backend}::version]
|
|  This program comes with ABSOLUTELY NO WARRANTY; for details type 'show license'
|  This is free software, and you are welcome to redistribute it
|  under certain conditions.
"

if {$::argc > 0} {
	call [string trim $::argv]
} else {
	read_loop
}

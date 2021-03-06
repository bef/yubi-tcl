#!/usr/bin/env tclsh
#
# check OTP with OpenSSH ForceCommand for two-factor authentication
# or check OTP via PAM with libpam-script / pam_script_auth
# or check OPT for OpenVPN via auth-user-pass-verify w/ method set to "via-env"
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
package require Tcl 8.5

set auto_path [linsert $auto_path 0 {*}[list /opt/yubi /opt/yubi-tcl /usr/lib/yubi-tcl /usr/local/lib/yubi-tcl [file join [info script] ..]]]
package require yubi
package require yubi::wsapi::client
::http::config -useragent "yubi-tcl client $::yubi::wsapi::client::version"

package require inifile

proc log {msg {level auth.notice}} {
	if {[info exists ::auth_user]} {set msg "$::auth_user: $msg"}
	exec logger -p $level -i -t OTP $msg
}

proc permission_denied {} {
	if {$::verbose_output} { puts stderr "permission denied." }
	## sleep a few random milliseconds to make timing attacks harder
	after [expr { int(1000 * rand()) }]
	exit 1
}

proc sanitize {s} {
	return [regsub -all -- {[^a-zA-Z0-9.@-_]} $s _]
}

## args
proc find_inifile {} {
	foreach arg $::argv {
		set kv [split $arg "="]
		if {[lindex $kv 0] eq "ini"} {return $v}
	}
}
set inifile [find_inifile]
if {$inifile eq ""} {set inifile "/opt/yubi/etc/authorized_yubi.ini"}
if {[info exists env(AUTHORIZED_YUBI)]} {set inifile $env(AUTHORIZED_YUBI)}

## get OTP string
set verbose_output 1
if {[info exists env(PAM_AUTHTOK)]} {
	## PAM authentication
	set auth_mode pam
	set input $env(PAM_AUTHTOK)
	set auth_user [sanitize $env(PAM_USER)]
	set verbose_output 0

} elseif {[info exists env(SSH_AUTH_OTP)]} {
	## SSH authentication
	set auth_mode ssh
	set input $env(SSH_AUTH_OTP)
	set auth_user [sanitize $env(USER)]

} elseif {[info exists env(username)] && [info exists env(password)]} {
	## OpenVPN auth-user-pass-verify w/ method set to "via-env"
	set auth_mode openvpn
	set input $env(password)
	set auth_user [sanitize $env(username)]

} else {
	set auth_mode terminal
	## get OTP from stdin
	puts -nonewline stdout "One-Time-Password: "
	flush stdout
	gets stdin input
	set auth_user [sanitize $env(USER)]
}

## too long input check
if {[string length $input] > 256} {
	log "input too long"
	permission_denied
}

## extract static password
set input_static ""
if {[string length $input] > 44} {
	set input_static [string range $input 0 [string length $input]-45]
	set input [string range $input end-43 end]
}

## normalize/un-dvorak input
if {[catch {
	set input [::yubi::normalize_modhex $input]
} res opts]} {
	log $res
	permission_denied
}

## check env (ssh mode)
if {$auth_mode eq "ssh"} {
	foreach v {SHELL} {
		if {![info exists env($v)]} {
			log "missing env($v)"
			permission_denied
		}
	}
}

## get config
set ini [::ini::open $inifile r]
if {![::ini::exists $ini "user:$auth_user"]} {
	log "missing user in $inifile"
	::ini::close $ini
	permission_denied
}
set global_config [::ini::get $ini global]
set user_config [::ini::get $ini "user:$auth_user"]
::ini::close $ini
set config [dict merge $global_config $user_config]

## check config
foreach key {api_key api_id api_url tokenids} {
	if {![dict exists $config $key]} {
		log "missing entry '$key' in $inifile"
		permission_denied
	}
	set $key [dict get $config $key]
}
set api_key [::yubi::base642hex $api_key]

## check tokenid
set tokenid [::yubi::tokenid $input]
if {[lsearch -exact $tokenids $tokenid] == -1} {
	log "unauthorized tokenid: $tokenid"
	permission_denied
}

## check static password
set static_password ""
foreach k [list "password:$tokenid" "password"] {
	if {[dict exists $config $k]} {
		set static_password [dict get $config $k]
		break
	}
}
if {[string compare $static_password $input_static] != 0} {
	log "static password incorrect"
	permission_denied
}

## validate input via validation server
if {[catch {
	set res [::yubi::wsapi::client::check $input $api_id $api_key $api_url]
	if {$res != 1} {
		log "validation failed. code $res"
		permission_denied
	}
} res opts]} {
	if {$::errorCode == "WS" || $::errorCode == "OTP"} {
		log "authentication failed: $res"
	} else {
		log $::errorInfo
	}
	permission_denied
}

log "success"

if {$auth_mode eq "ssh"} {
	## success -> check for SSH_ORIGINAL_COMMAND
	if {[catch {package require Tclx}]} {
		puts stderr "sorry. contact your system administrator."
		log "Tclx not installed :("
		exit
	}
	proc special_exec {cmd args} {execl $cmd $args}

	if {[info exists env(SSH_ORIGINAL_COMMAND)]} {
		special_exec {*}$env(SSH_ORIGINAL_COMMAND)
	} else {
		special_exec $env(SHELL) -l
	}
}

exit 0


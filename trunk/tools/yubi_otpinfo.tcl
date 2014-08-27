#!/usr/bin/env tclsh
#
# print information about an OTP string
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

set auto_path [linsert $auto_path 0 [file join [file dirname $::argv0] ..]]
package require yubi

proc print_kv {data} {
	foreach {k v} $data {
		puts [format "%-20s %s" $k $v]
	}
}


puts -nonewline "Enter OTP: "
flush stdout
gets stdin input

# set input {jxe.uidchtnbpygkdediddnyjjekxnhpykehhggjkgxttpigybkntb}
set input [string trim [string tolower $input]]
set orig_input $input

if {[catch {
	set keymap [::yubi::find_keymap $input]
} result opts]} {
	puts "error: $result"
	exit
}
if {[string range $input 0 15] == $keymap} {
	set input [string range $input 16 end]
}

set input [::yubi::modhex_decode $input $keymap]

set public_identity "<empty>"
if {[string length $input] > 32} {
	set public_identity [string range $input 0 end-32]
	set input [string range $input end-31 end]
}

puts "====\[ OTP info \]===="
print_kv [list \
	input $orig_input \
	"normalized input" [::yubi::modhex_encode [::yubi::modhex_decode $orig_input $keymap]] \
	"modhex-decoded input" [::yubi::modhex_decode $orig_input $keymap] \
	keymap $keymap \
	"public identity" "$public_identity | [::yubi::modhex_encode $public_identity] (modhex) | [::yubi::modhex_encode $public_identity $::yubi::dvorak_keymap] (modhex dvorak)" \
	OTP $input \
	]
	

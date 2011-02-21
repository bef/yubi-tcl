#!/usr/bin/tclsh8.5
#
# convert hex <-> base64
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

set auto_path [linsert $auto_path 0 [file join [file dirname $::argv0] ..]]
package require yubi

if {[llength $argv] != 2} {
	puts "$argv0 <-h2b|-b2h|-h2m|-m2h> <string>"
	puts "  convert hex <-> base64 OR hex <-> modhex"
	exit 1
}

switch -- [lindex $argv 0] {
	-h2b {puts [::yubi::hex2base64 [lindex $argv 1]]}
	-b2h {puts [::yubi::base642hex [lindex $argv 1]]}
	-h2m {puts [::yubi::modhex_encode [lindex $argv 1]]}
	-m2h {puts [::yubi::modhex_encode [lindex $argv 1]]}
	default {puts "invalid direction"; exit 1}
}

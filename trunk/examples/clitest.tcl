#!/usr/bin/tclsh

set auto_path [linsert $auto_path 0 [file join [file dirname $::argv0] ..]]
package require yubi

set aeskey "a75bab9004c818850b0b549e32c4491c"

puts "ready."
while {[gets stdin input] >= 0} {
	if {[catch {
		puts [::yubi::mhdecode $aeskey $input]
	} result opts]} {
		if {$::errorCode == "OTP"} {
			puts "error: $result"
			puts "API response: [dict get $opts api_response]"
		} else {
			puts $::errorInfo
		}
	}
}



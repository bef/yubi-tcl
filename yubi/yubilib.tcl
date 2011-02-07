#
# library for yubikey-compatible server and client implementations
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

package require struct::list
package require aes
package require sha1
package require base64

namespace eval ::yubi {
	variable version 0.1

	## modhex encoding template
	variable hexdigits {0123456789abcdef}
	variable us_keymap {cbdefghijklnrtuv}
	variable dvorak_keymap {jxe.uidchtnbpygk}
	variable neo2_keymap {äzaleosgnrtbcwhp}
	variable all_keymaps [list $us_keymap $dvorak_keymap $neo2_keymap]
}

## zip two lists of same length as in {a b c} {1 2 3} -> {a 1 b 2 c 3}
proc ::yubi::lzip {l1 l2} {
	set ret {}
	for {set i 0} {$i < [llength $l1]} {incr i} {
		lappend ret [lindex $l1 $i] [lindex $l2 $i]
	}
	return $ret
}

## CRC16
proc ::yubi::ycrc {s} {
	set crc 0xffff
	binary scan $s c* data
	foreach {c} $data {
		set c [expr {$c & 0xff}]
		set crc [expr {$crc ^ $c}]
		for {set i 0} {$i < 8} {incr i} {
			set j [expr {$crc & 1}]
			set crc [expr {$crc >> 1}]
			if {$j} {
				set crc [expr {$crc ^ 0x8408}]
			}
		}
	}
	return $crc
}

## check if all characters of the string are distinct
proc ::yubi::is_valid_keymap {km} {
	for {set i 0} {$i < [string length $km]} {incr i} {
		if {[string first [string index $km $i] $km $i+1] >= 0} {
			return 0
		}
	}
	return 1
}

## find keymap
proc ::yubi::find_keymap {in} {
	variable all_keymaps
	set len [string length $in]

	set check_keymaps $all_keymaps

	if {$len < 32 || $len > 64} {
		return -code error -errorcode OTP -options {api_response BAD_OTP} "invalid OTP length"
	}

	if {$len >= 48} {
		## first 16 bytes may be the correct mapping
		set keymap [string range $in 0 15]
		if {[is_valid_keymap $keymap]} {
			lappend check_keymaps $keymap
		}
	}

	## guess keymap
	set lin [split $in {}]
	foreach {keymap} $check_keymaps {
		set found 1
		foreach {c} $lin {
			if {[string first $c $keymap] < 0} {set found 0; continue}
		}
		if {$found} {return $keymap}
	}

	return -code error -errorcode OTP -options {api_response BAD_OTP} "cannot guess keymap"
}

## convert hex string to binary
proc ::yubi::hex2bin {v} {
	return [binary format H* $v]
}

## convert binary string to hex
proc ::yubi::bin2hex {v} {
	binary scan $v H* ret
	return $ret
}

## decode OTP
## OTP format: [A][B]C
##    where A is an optional mapping of 0..f to modhex digits (0 or 16 bytes) ("cbdefghijklnrtuv" on US-keymap)
##          B is an optional fixed string (0 to 16 bytes)
##          C is the mandatory encrypted OTP string
proc ::yubi::mhdecode {aeskey in} {
	variable hexdigits
	variable us_keymap

	## lower case + no whitespace
	set in [string tolower [string trim $in]]

	## find keymap
	set keymap [find_keymap $in]
	if {[string length $in] > 32} {
		set in [string range $in end-31 end]
	}

	## unmap
	set mhmap [lzip [split $keymap {}] [split $hexdigits {}]]
	set hexencdata [string map $mhmap $in]

	## check for valid hex characters
	## OBSOLETE: find_keymap checks for valid mapping
	# if {![string is xdigit $hexencdata]} {return -code error -errorcode OTP -options {api_response BAD_OTP} "invalid modhex encoding"}

	## decrypt
	set encdata [hex2bin $hexencdata]
	set data [aes::aes -mode ecb -dir decrypt -key [binary format H* $aeskey] -- $encdata]

	## check crc -- must be 0xf0b8
	set crc [ycrc $data]
	if {[ycrc $data] != 0xf0b8} {return -code error -errorcode OTP -options {api_response BAD_OTP} "incorrect CRC"}

	## prepare result
	binary scan [string range $data 6 7] s ctr
	set ctr [expr {$ctr & 0x7fff}]
	set tstp [expr "0x[bin2hex [string reverse [string range $data 8 10]]]"]
	binary scan [string range $data 11 11] c use
	set use [expr {$use & 0xff}]
	set otp [string map [lzip [split $hexdigits {}] [split $keymap {}]] $hexencdata]
	set usotp [string map [lzip [split $hexdigits {}] [split $us_keymap {}]] $hexencdata]
	return [list uid [bin2hex [string range $data 0 5]] \
		ctr  $ctr \
		tstp $tstp \
		use  $use \
		rnd  [bin2hex [string range $data 12 13]] \
		crc  [bin2hex [string range $data 14 15]] \
		otp  $otp \
		usotp $usotp]
}

## assemble query string sorted by key
## and calculate base64 encoded SHA-1 HMAC
proc ::yubi::api_hmac {apikey params} {
	set kv {}
	foreach k [lsort [dict keys $params]] {
		lappend kv "$k=[dict get $params $k]"
	}
	set line [join $kv "&"]
	set hmac [::sha1::hmac -bin -key [hex2bin $apikey] $line]

	return [::base64::encode -maxlen 0 $hmac]
}

## generate random hex string
proc ::yubi::nonce {{length 32}} {
	set ret ""
	for {set i 0} {$i < $length} {incr i} {
		set rnd [expr {int(16*rand())}]
		set ret ${ret}[string index {0123456789abcdef} $rnd]
	}
	return $ret
}

## generate ISO 8601 UTC timestamp
proc ::yubi::timestamp {} {
	return [clock format [clock seconds] -format {%Y-%m-%dT%H:%M:%S} -timezone :UTC]
}

## (lazy)scan ISO 8601 UTC timestamp
proc ::yubi::scan_timestamp {t} {
	set ts [regexp -inline -- {(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:Z\d+)?} $t]
	if {$ts == ""} {return ""}
	return [clock scan [lindex $ts 1] -format {%Y-%m-%dT%H:%M:%S} -timezone :UTC]
}

## convert base64 encoded string to hex encoded string
## (to convert base64 encoded api keys to hex as needed for this library)
proc ::yubi::base642hex {s} {
	return [bin2hex [::base64::decode $s]]
}

## convert hex to base64
proc ::yubi::hex2base64 {s} {
	return [::base64::encode -maxlen 0 [hex2bin $s]]
}

## normalize/re-map modhex encoded string (e.g. dvorak -> us)
proc ::yubi::remap_modhex {s} {
	variable hexdigits
	variable us_keymap
	set keymap [find_keymap $s]
	set mhmap [lzip [split $keymap {}] [split $hexdigits {}]]
	set hexencdata [string map $mhmap $s]
	set mhunmap [lzip [split $hexdigits {}] [split $us_keymap {}]]
	return [string map $mhunmap $hexencdata]
}


package provide yubi $::yubi::version

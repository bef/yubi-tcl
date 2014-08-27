#!/usr/bin/env tclsh
package require Tcl 8.5

set auto_path [linsert $auto_path 0 [file join [file dirname $::argv0] ..]]
package require yubi
package require yubi::wsapi::client
::http::config -useragent "yubi-tcl client $::yubi::wsapi::client::version"

#### example test-case with local server
set api_url {http://devvm:88/cgi-bin/yubiverify2.0.tcl}
set api_id 1
set api_key da5d1a9407db6df1b547c0daefb6298a
proc input_preprocessing {in} {return $in}

#### example test-case with yubico wsapi server
# set api_url {http://api.yubico.com/wsapi/2.0/verify}
# set api_id 1234
# set api_key [::yubi::base642hex {MWFjYTI0OWEzMzJmZWQ5NzUyOWM0NzcyZDk2NTM4OTE=}]
# proc input_preprocessing {in} {
# 	## un-dvorak input for neglecting api servers
# 	return [::yubi::normalize_modhex $in]
# }

#### hardcoded input for faster debugging
# set input "jxe.uidchtnbpygkdediddgb.phu.ypx.gkutntbb.j.jtjiy.tbhu"
# set input "jxe.uidchtnbpygkdediddeyjjdjietegx.b.niuep.pixgccegtub"
# puts $input
# puts [::yubi::wsapi::client::check $input $api_id $api_key $api_url]
# exit

proc print_kv {data {headline {}} {indent {  }}} {
	if {$headline != ""} {puts $headline}
	foreach {k v} $data {
		puts [format "%s%-20s %s" $indent $k $v]
	}
}

puts "==\[ ready \]=="
while {[gets stdin input] >= 0} {
	if {[catch {
		set input [input_preprocessing $input]
		
		set tokenid [::yubi::tokenid [::yubi::normalize_modhex $input]]
		puts "==\[ checking token ID $tokenid \]=="
		
		set result [::yubi::wsapi::client::check $input $api_id $api_key $api_url {timestamp 1 ext 1}]
		
		print_kv $::yubi::wsapi::client::last_request "  --\[ request \]--"
		print_kv $::yubi::wsapi::client::last_response "  --\[ response \]--"
		
		if {$result != 1} {
			puts "==\[ validation failed. code $result \]=="
		} else {
			puts "==\[ success \]=="
		}
	} result opts]} {
		if {$::errorCode == "WS" || $::errorCode == "OTP"} {
			puts "==\[ error: $result \]=="
		} else {
			puts $::errorInfo
		}
	}
}

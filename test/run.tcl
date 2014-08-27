#!/usr/bin/env tclsh
package require Tcl 8.5
if {[lsearch -exact $auto_path {..}] < 0} {
	set auto_path [linsert $auto_path 0 [file join [file dirname [info script]] ..]]
}
package require tcltest 2.2

::tcltest::configure -testdir \
	[file dirname [file normalize [info script]]]
eval ::tcltest::configure $argv
::tcltest::runAllTests

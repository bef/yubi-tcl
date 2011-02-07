if {![package vsatisfies [package provide Tcl] 8.5]} {return}

package ifneeded yubi 0.1 "source [file join $dir yubilib.tcl]; source [file join $dir yubi_wsapi.tcl]"

package ifneeded yubi::wsapi::backend_dummy 0.1 [list source [file join $dir yubi_wsapi_backend_dummy.tcl]]
package ifneeded yubi::wsapi::backend_file 0.1 [list source [file join $dir yubi_wsapi_backend_file.tcl]]
package ifneeded yubi::wsapi::client 0.1 [list source [file join $dir yubi_wsapi_client.tcl]]

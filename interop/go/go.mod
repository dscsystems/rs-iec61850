module rsiec61850/interop

go 1.26.5

require github.com/dscsystems/go-iec61850 v0.0.0

require golang.org/x/sys v0.47.0 // indirect

// interop/go-security.sh points this at the go-iec61850 checkout.
replace github.com/dscsystems/go-iec61850 => ../../../go-iec61850

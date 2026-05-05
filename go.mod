module apigo.cc/go/crypto

go 1.25.0

require (
	apigo.cc/go/encoding v1.0.5
	apigo.cc/go/safe v1.0.5
	golang.org/x/crypto v0.50.0
)

require (
	apigo.cc/go/rand v1.0.5 // indirect
	golang.org/x/sys v0.43.0 // indirect
)

replace apigo.cc/go/encoding => ../encoding

replace apigo.cc/go/safe => ../safe

replace apigo.cc/go/rand => ../rand

/*
to run these scripts, do:

go build .
./examples script...
*/
package main

import (
	"flag"
)

const (
	metrics            = "metrics"
	multiplicative     = "multiplicative"
	additiveSequential = "additive-sequential"
	additiveBrokered   = "additive-brokered"
)

func main() {
	flag.Parse()
	scripts := flag.Args()
	for _, script := range scripts {
		switch script {
		case metrics:
			runMetrics()
		case multiplicative:
			runMultiplicative()
		case additiveSequential:
			runAdditiveSequential()
		case additiveBrokered:
			runAdditiveBrokered()
		}
	}
}

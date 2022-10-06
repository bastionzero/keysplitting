/*
to run these scripts, do:

go build .
./examples script1 script2 ...
*/
package main

import (
	"flag"
)

const (
	metrics = "metrics"
)

func main() {
	flag.Parse()
	scripts := flag.Args()
	for _, script := range scripts {
		switch script {
		case metrics:
			runMetrics()
		}
	}
}

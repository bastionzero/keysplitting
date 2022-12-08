package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	mrand "math/rand"

	"encoding/json"
	"fmt"
	"runtime"
	"time"

	"github.com/bastionzero/keysplitting"
)

// source: https://scene-si.org/2018/08/06/basic-monitoring-of-go-apps-with-the-runtime-package/
type Monitor struct {
	Alloc,
	TotalAlloc,
	Sys,
	Mallocs,
	Frees,
	LiveObjects,
	PauseTotalNs uint64

	NumGC        uint32
	NumGoroutine int
}

func NewMonitor(duration int) {
	var m Monitor
	var rtm runtime.MemStats
	var interval = time.Duration(duration) * time.Second
	for {
		<-time.After(interval)

		// Read full mem stats
		runtime.ReadMemStats(&rtm)

		// Number of goroutines
		m.NumGoroutine = runtime.NumGoroutine()

		// Misc memory stats
		m.Alloc = rtm.Alloc
		m.TotalAlloc = rtm.TotalAlloc
		m.Sys = rtm.Sys
		m.Mallocs = rtm.Mallocs
		m.Frees = rtm.Frees

		// Live objects = Mallocs - Frees
		m.LiveObjects = m.Mallocs - m.Frees

		// GC Stats
		m.PauseTotalNs = rtm.PauseTotalNs
		m.NumGC = rtm.NumGC

		// Just encode to json and print
		b, _ := json.Marshal(m)
		fmt.Println(string(b))
	}
}

func runMetrics() {
	fmt.Println("Running metrics script -- a continuous random workflow to sanity check memory usage and other statistics")
	msg := "test message"
	hasher := sha512.New()
	hasher.Write([]byte(msg))
	hashed := hasher.Sum(nil)

	go NewMonitor(30)
	mrand.Seed(time.Hour.Microseconds())

	for {
		key, _ := rsa.GenerateKey(rand.Reader, 4096)
		nShards := mrand.Intn(128)
		shards, err := keysplitting.SplitD(key, nShards, keysplitting.Addition)
		if err != nil {
			panic(err)
		}

		// although the overall order doesn't matter, someone has to make the first signature
		sig1, err := keysplitting.SignFirst(rand.Reader, shards[0], crypto.SHA512, hashed)
		if err != nil {
			panic(err)
		}

		// simulate each party iteratively adding their signature
		sigNext := sig1
		for k := 1; k < len(shards); k++ {
			sigNext, err = keysplitting.SignNext(rand.Reader, shards[k], crypto.SHA512, hashed, keysplitting.Addition, sigNext)
			if err != nil {
				panic(err)
			}
		}
		err = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA512, hashed, sigNext)
		if err != nil {
			panic(err)
		}
	}
}

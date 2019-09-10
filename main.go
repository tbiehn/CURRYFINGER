/*
* Copyright 2019, Travis Biehn
* All rights reserved.
*
* This source code is licensed under the MIT license found in the
* LICENSE file in the root directory of this source tree.
*
 */

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/corpix/uarand"

	"github.com/texttheater/golang-levenshtein/levenshtein"
)

var e = log.New(os.Stderr, "", 0)
var l = log.New(os.Stdout, "", 0)

var timeout = flag.Duration("timeout", 30*time.Second, "Timeout the check.")
var keepalive = 0 * time.Millisecond

var DefBits = flag.Int("mbits", 500, "Match in the first -mbits.")

var Threshold = flag.Int("perc", 50, "Match at -perc[entage] similarity")

var Threads = flag.Int("threads", 200, "Number of -threads to use.")

var ShowSample = flag.Bool("show", false, "Show sample responses.")

var UserAgent = flag.String("ua", "", "Specify User Agent, otherwise we'll generate one.")

func main() {
	e.Print(ban)

	reconfile := flag.String("file", "", "read ips from specified -file instead of stdin.")
	domain := flag.String("url", "https://example.org", "-url to check.")

	flag.Parse()

	inputStream := os.Stdin
	if strings.EqualFold(*UserAgent, "") {
		rand := uarand.Default.GetRandom()
		UserAgent = &rand
	}

	e.Print("[I] Starting on ", *domain, " with UA ", *UserAgent)

	if !strings.EqualFold(*reconfile, "") {
		var err error
		inputStream, err = os.Open(*reconfile)
		if err != nil {
			e.Println("Could not open specified file", *reconfile)
			e.Fatal(err)
		}
	}

	bits, err := ioutil.ReadAll(inputStream)
	if err != nil {
		e.Println("Could not read all the bits")
		e.Fatal(err)
	}

	testIps := strings.Split(strings.Replace(string(bits), "\r\n", "\n", -1), "\n")

	var wg sync.WaitGroup

	wg.Add(1)

	go test(&wg, *domain, testIps)

	wg.Wait()
}

func test(wg *sync.WaitGroup, target string, testIPs []string) {
	defer wg.Done()

	//Vanilla.
	dialer := &net.Dialer{
		Timeout:   *timeout,
		KeepAlive: keepalive,
		DualStack: true,
	}
	transport := &http.Transport{
		Dial: dialer.Dial,
	}
	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	client := http.Client{
		Timeout:   *timeout,
		Transport: transport,
	}

	req, err := http.NewRequest("GET", target, nil)
	req.Header.Set("User-Agent", *UserAgent)

	res, err := client.Do(req)

	og := ""
	if err != nil {
		e.Print(err)
	} else {
		reader := io.LimitReader(res.Body, int64(*DefBits))
		bits, err := ioutil.ReadAll(reader)
		if err != nil {
			e.Print(err)
		}
		og = string(bits)
	}

	client.CloseIdleConnections()
	transport.CloseIdleConnections()

	jobs := make(chan AssessParcel, len(testIPs))
	for w := 1; w <= *Threads; w++ {
		go assessWorker(w, jobs)
	}
	var workerGroup sync.WaitGroup

	workerGroup.Add(len(testIPs))
	for _, ip := range testIPs {
		jobs <- AssessParcel{
			OriginalContent: og,
			Target:          target,
			TestIP:          ip,
			Wg:              &workerGroup,
		}
	}

	close(jobs)
	workerGroup.Wait()
}

type AssessParcel struct {
	OriginalContent string
	Target          string
	TestIP          string
	Wg              *sync.WaitGroup
}

func assessWorker(id int, jobs <-chan AssessParcel) {
	for j := range jobs {
		ip := net.ParseIP(j.TestIP)
		if ip != nil {
			e.Print("[T@", id, "] Is ", j.Target, " hosted on ", j.TestIP, "?")
			assess(j.OriginalContent, j.Target, ip.String())
		}
		j.Wg.Done()
	}
}

func assess(og string, target string, testIP string) {

	//Jacked.

	jackedDialer := &net.Dialer{
		Timeout:   *timeout,
		KeepAlive: keepalive,
		DualStack: true,
	}

	jackedTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// redirect all connections to 127.0.0.1
			addr = testIP + addr[strings.LastIndex(addr, ":"):]
			return jackedDialer.DialContext(ctx, network, addr)
		},
	}
	jackedTransport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	jackedClient := http.Client{
		Timeout:   *timeout,
		Transport: jackedTransport,
	}

	req, err := http.NewRequest("GET", target, nil)
	req.Header.Set("User-Agent", *UserAgent)

	res, err := jackedClient.Do(req)

	jacked := ""
	if err != nil {
		e.Print(err)
	} else {
		reader := io.LimitReader(res.Body, int64(*DefBits))

		bits, err := ioutil.ReadAll(reader)
		if err != nil {
			e.Print(err)
		}
		jacked = string(bits)
	}

	jackedClient.CloseIdleConnections()
	jackedTransport.CloseIdleConnections()

	matchBits := *DefBits

	if len(og) < matchBits || len(jacked) < matchBits {
		matchBits = len(og)
		if len(jacked) < len(og) {
			matchBits = len(jacked)
		}
	}

	if matchBits < 5 {
		e.Print("[E] ", testIP, "==", target, " Not enough bytes to be meaningful. len(og): ", len(og), " len(jacked): ", len(jacked))
		l.Print("miss ", testIP, " ", target, " ", 0, " percent in ", 0, " bytes")
		return
	}

	distance := levenshtein.DistanceForStrings([]rune(og[:matchBits]), []rune(jacked[:matchBits]), levenshtein.DefaultOptions)

	matchy := 100 - int(float32(float32(distance)/float32(matchBits))*100)

	e.Print("[I] ", testIP, "==", target, " Similarity in first ", matchBits, " bits computed as: ", matchy, "% @ distance: ", distance)

	if *ShowSample {
		e.Print("[D] Original Sample:")
		e.Print(og[:matchBits])
		e.Print("[D] Measurement Sample:")
		e.Print(jacked[:matchBits])
	}
	if matchy > 50 {
		l.Print("match ", testIP, " ", target, " ", matchy, " percent in ", matchBits, " bytes")
	} else {
		l.Print("miss ", testIP, " ", target, " ", matchy, " percent in ", matchBits, " bytes")
	}
}

var ban = `
   mmm  m    m mmmmm  mmmmm m     m mmmmmm mmmmm  mm   m   mmm  mmmmmm mmmmm
 m"   " #    # #   "# #   "# "m m"  #        #    #"m  # m"   " #      #   "#
 #      #    # #mmmm" #mmmm"  "#"   #mmmmm   #    # #m # #   mm #mmmmm #mmmm"
 #      #    # #   "m #   "m   #    #        #    #  # # #    # #      #   "m
  "mmm" "mmmm" #    " #    "   #    #      mm#mm  #   ##  "mmm" #mmmmm #    "

dualuse.io - FINE DUAL USE TECHNOLOGIES`

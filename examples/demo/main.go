// Command demo is a tiny local web app used to test kproxy tunnels.
// Run it, then expose it with: kproxy http 8082
package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	addr := ":8082"
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<!doctype html><html><head><title>kproxy demo</title></head>
<body><h1>kproxy demo app</h1><p>You are viewing a locally-served app through a kproxy tunnel.</p>
<p>Requested path: %s</p></body></html>`, r.URL.Path)
	})
	log.Printf("demo app listening on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}
package main

import (
	"io/ioutil"
	"os"

	"fmt"
	"net/http"

	gsshttp "github.com/nalind/gss/pkg/gss/http"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: www-authenticate URL")
		return
	}

	req, err := http.NewRequest("GET", os.Args[1], nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	client := &http.Client{Transport: gsshttp.NewNegotiateRoundTripper(http.DefaultTransport)}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("reading reponse body: %v\n", err)
	}
	fmt.Println(string(body))
}

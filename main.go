package main

import "./mysocks5"

func main() {
	config := &mysocks5.Config{}
	server, err := mysocks5.New(config)
	if err != nil {
		panic(err)
	}
	if err := server.ListenAndServe("tcp", "0.0.0.0:2080"); err != nil {
		panic(err)
	}
}

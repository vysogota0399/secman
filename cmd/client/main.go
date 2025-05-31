package main

import (
	"os"

	"github.com/vysogota0399/secman/internal/client"
)

func main() {
	client.Process(os.Args[1:], client.AllCommands, client.NewSession())
}

package main

import (
	"os"

	"github.com/vysogota0399/secman/internal/cli"
	"github.com/vysogota0399/secman/internal/logging"
)

func main() {
	cfg, err := cli.NewConfig()
	if err != nil {
		os.Stderr.WriteString("Failed to load config: " + err.Error() + "\n")
		return
	}

	lg, err := logging.MustZapLogger(cfg)
	if err != nil {
		os.Stderr.WriteString("Failed to create logger: " + err.Error() + "\n")
		return
	}

	s, err := cli.NewSession(cfg, lg)
	if err != nil {
		os.Stderr.WriteString("Failed to create session: " + err.Error() + "\n")
		return
	}

	client, err := cli.NewClient(s, cfg)
	if err != nil {
		os.Stderr.WriteString("Failed to create client: " + err.Error() + "\n")
		return
	}

	cli.Run(
		os.Args[1:],
		cli.AllCommands,
		s,
		lg,
		cfg,
		client,
	)
}

package client

import (
	"os"
	"strings"
)

func Process(args []string) {
	b := &strings.Builder{}

	if len(args) == 0 {
		b.WriteString("Usage: secman <command> <subcommand> <args>\n\n")
		b.WriteString("These are common secman commands used in various situations:\n\n")
		for name, command := range AllCommands {
			b.WriteString(name + ", " + command.Info + "\n")

			for sName, subcommand := range command.Subcommands {
				b.WriteString("- " + sName + ", " + subcommand.Info + "\n")
			}

			b.WriteString("\n")
			os.Stdout.WriteString(b.String())
			return
		}

		command, ok := AllCommands[args[0]]
		if !ok {
			b.WriteString("Unknown command: " + args[0] + "\n\n")
			os.Stdout.WriteString(b.String())
			return
		}

		if err := command.Handler(args[1:], b); err != nil {
			b.WriteString("Failed: " + err.Error() + "\n\n")
		}

		os.Stdout.WriteString(b.String())
		return
	}
}

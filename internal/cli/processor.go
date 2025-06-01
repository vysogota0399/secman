package cli

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	"github.com/vysogota0399/secman/internal/logging"
	"go.uber.org/zap"
)

type ISession interface {
	Init(ctx context.Context) error
	Persist() error
	GetToken() string
	SetRootToken(token string)
	GetSecrets() map[string]string
	Set(key, value string)
	Get(key string) string
	Authenticate(m map[string]string) error
	TruncateSecrets()
}

type Operation struct {
	Session ISession
	Client  IClient
	Logger  *log.Logger
}

func NewOperation(s ISession, c IClient) *Operation {
	return &Operation{
		Session: s,
		Client:  c,
	}
}

func Run(
	args []string,
	cmds map[string]ICommand,
	s ISession,
	lg *logging.ZapLogger,
	c *Config,
	client IClient,
) {
	b := &strings.Builder{}

	if len(args) == 0 {
		b.WriteString("Usage: secman <command> <subcommand> <args>\n\n")
		b.WriteString("These are common secman commands used in various situations:\n\n")
		for name, command := range cmds {
			b.WriteString("- " + name + ": " + command.Info() + "\n")
		}

		os.Stdout.WriteString(b.String())
		return
	}

	command, ok := cmds[args[0]]
	if !ok {
		b.WriteString("Unknown command: " + args[0] + "\n\n")
		os.Stdout.WriteString(b.String())
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	lg.DebugCtx(ctx, "starting operation", zap.String("command", args[0]))

	if err := s.Init(ctx); err != nil {
		b.WriteString("Failed to initialize session: " + err.Error() + "\n\n")
		os.Stderr.WriteString(b.String())
		return
	}

	if err := command.Parse(args); err != nil {
		b.WriteString("Parse failed: " + err.Error())
		os.Stderr.WriteString(b.String())
		return
	}

	op := NewOperation(s, client)

	if err := command.Handle(ctx, b, op); err != nil {
		b.WriteString("Failed: " + err.Error())
	}

	if err := s.Persist(); err != nil {
		b.WriteString("Failed to save session: " + err.Error())
		os.Stderr.WriteString(b.String())
		return
	}

	os.Stdout.WriteString(b.String() + "\n")
}

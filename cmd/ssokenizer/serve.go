package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/superfly/ssokenizer"
)

const gracefulShutdownTimeout = 5 * time.Second

type ServeCommand struct {
	Config Config
}

// NewServeCommand returns a new instance of ServeCommand.
func NewServeCommand() *ServeCommand {
	return &ServeCommand{
		Config: NewConfig(),
	}
}

func (c *ServeCommand) Run(args []string) error {
	fs := flag.NewFlagSet("ssokenizer-serve", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/ssokenizer.yml", "config file path")
	debug := fs.Bool("debug", false, "enable debug logging")
	fs.Usage = func() {
		fmt.Println(`
The serve command will run ssokenizer. It will read configuration from the
ssokenizer.yml file. This file should in /etc/ssokenizer.yml or specified
with the -config flag.

Usage:

	ssokenizer serve [arguments]

Arguments:
`[1:])
		fs.PrintDefaults()
		fmt.Println("")
	}
	if err := fs.Parse(args); err != nil {
		return err
	} else if fs.NArg() > 0 {
		return fmt.Errorf("too many arguments")
	}

	// Read configuration.
	buf, err := os.ReadFile(*configPath)
	if err != nil {
		return err
	} else if err := UnmarshalConfig(&c.Config, buf); err != nil {
		return err
	}
	if err := c.Config.Validate(); err != nil {
		return err
	}

	// Override debug logging, if set.
	if *debug {
		c.Config.Log.Debug = true
	}
	logrus.SetLevel(logrus.DebugLevel)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	server := ssokenizer.NewServer(c.Config.SealKey, c.Config.RelyingPartyAuth)

	for name, p := range c.Config.IdentityProviders {
		returnURL := p.ReturnURL
		if returnURL == "" {
			returnURL = strings.ReplaceAll(c.Config.ReturnURL, ":name", name)
		}

		pc, err := p.providerConfig(name, returnURL)
		if err != nil {
			return err
		}
		server.AddProvider(name, pc, returnURL)
	}

	if err := server.Start(c.Config.HTTP.Address); err != nil {
		return err
	}

	logrus.Infof("listening at %s", server.Address)

	select {
	case <-server.Done:
		logrus.Warn("early shutdown")
		return server.Err
	case <-ctx.Done():
		logrus.Info("received signal. starting shutdown")

		ctx, cancel = context.WithTimeout(context.Background(), gracefulShutdownTimeout)
		defer cancel()

		ctx, cancel = signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
		defer cancel()

		return server.Shutdown(ctx)
	}
}

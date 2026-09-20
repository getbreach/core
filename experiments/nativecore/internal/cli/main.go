package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"breach-nativecore/engine"
	"breach-nativecore/geodata"
	"breach-nativecore/internal/dashboard"
	"breach-nativecore/systemtun"
)

func Main(defaultMode string) {
	if err := run(os.Args[1:], defaultMode); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, flag.ErrHelp) {
		log.Fatal(err)
	}
}

func run(args []string, defaultMode string) error {
	command := "run"
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		command = args[0]
		args = args[1:]
	}
	switch command {
	case "internal-route-guardian":
		if len(args) != 0 {
			return errors.New("route guardian takes no arguments")
		}
		return systemtun.RunRouteGuardian(os.Stdin, os.Stdout)
	case "run", "check", "tui":
		f := flag.NewFlagSet("breach "+command, flag.ContinueOnError)
		path := f.String("config", "", "private JSON config")
		if err := f.Parse(args); err != nil {
			return err
		}
		if *path == "" || f.NArg() != 0 {
			return errors.New("usage: breach " + command + " -config /path/to/config.json")
		}
		cfg, err := engine.Load(*path, defaultMode)
		if err != nil {
			return err
		}
		if command == "check" {
			fmt.Println("Configuration valid")
			return nil
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if command == "tui" {
			return dashboard.Run(ctx, cfg)
		}
		return engine.Run(ctx, cfg, log.Printf)
	case "convert-geodata":
		f := flag.NewFlagSet(command, flag.ContinueOnError)
		input := f.String("input", "", "V2Ray/Xray .dat file")
		kind := f.String("kind", "geosite", "geosite or geoip")
		category := f.String("category", "", "one category; empty converts all")
		dir := f.String("out", "", "output directory for native JSON sets")
		if err := f.Parse(args); err != nil {
			return err
		}
		if *input == "" || *dir == "" || f.NArg() != 0 {
			return errors.New("-input and -out are required")
		}
		tags, err := geodata.Convert(*input, *kind, *category, *dir)
		if err != nil {
			return err
		}
		fmt.Println(tags)
		return nil
	default:
		return fmt.Errorf("unknown command %q; use run, tui, check or convert-geodata", command)
	}
}

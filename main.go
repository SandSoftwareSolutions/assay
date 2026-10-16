// hallmark shows whether files were changed.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/SandSoftwareSolutions/hallmark/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	app := &cli.App{Out: os.Stdout, Err: os.Stderr}
	code := app.Run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}

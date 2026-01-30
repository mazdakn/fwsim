package main

import (
	"flag"
	"os"

	"github.com/mazdakn/fwsim/pkg/engine"
	"github.com/sirupsen/logrus"
)

const (
	defaultInputFile = "rules.yaml"
)

func main() {
	input := flag.String("i", defaultInputFile, "input file with all rules and packets")
	flag.Parse()

	if input == nil || len(*input) == 0 {
		logrus.Errorf("No input file")
		os.Exit(1)
	}

	e := engine.New(*input)
	e.Validate()
}

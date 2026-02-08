package main

/*const (
	defaultInputFile = "rules.yaml"
)

func main() {
	input := flag.String("i", defaultInputFile, "input file with all rules and packets")
	flag.Parse()

	if input == nil || len(*input) == 0 {
		logrus.Errorf("No input file")
		os.Exit(1)
	}

	e := engine.New()

	err := e.LoadConfig(*input)
	if err != nil {
		logrus.WithError(err).Errorf("failed to load config %s", *input)
		os.Exit(1)
	}
	e.Validate()
}*/

import (
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
)

// Example struct with embedded CEL tags
type ValidationRules struct {
	Username string `cel:"name.startsWith('user_')"`
	Age      int    `cel:"age >= 18"`
}

func main() {
	// 1. Set up the CEL environment
	env, _ := cel.NewEnv(
		cel.Variable("name", cel.StringType),
		cel.Variable("age", cel.IntType),
	)

	// 2. Sample data to check
	input := map[string]interface{}{
		"name": "user_admin",
		"age":  25,
	}

	// 3. Reflect on the struct to get the tag and evaluate
	rules := ValidationRules{}
	t := reflect.TypeOf(rules)
	field, _ := t.FieldByName("Username")
	tag := field.Tag.Get("cel") // Gets "name.startsWith('user_')"

	// 4. Compile and evaluate the CEL expression from the tag
	ast, _ := env.Compile(tag)
	prg, _ := env.Program(ast)
	out, _, _ := prg.Eval(input)

	fmt.Println("Result:", out.Value()) // Output: Result: true
}

// internal/engine/engine.go

package engine

import (
	"fmt"
)

type Template struct {
	Steps []Step `yaml:"steps"`
}

type Step struct {
	ID        string                 `yaml:"id"`
	Module    string                 `yaml:"module"`
	Input     map[string]interface{} `yaml:"input"`
	Condition string                 `yaml:"condition"`
}

type Result struct {
	Success bool
	Data    map[string]interface{}
	Error   error
}

type Context struct {
	Results map[string]Result
}

// Interface Module
type Module interface {
	Run(ctx *Context, input map[string]interface{}) (Result, error)
}

// =========================
// 🚀 RUN ENGINE
// =========================

func RunTemplate(t Template, modules map[string]Module) error {
	ctx := &Context{
		Results: make(map[string]Result),
	}

	for _, step := range t.Steps {

		fmt.Printf("[*] Running step: %s\n", step.ID)

		// 1. Condition
		if step.Condition != "" {
			if !EvaluateCondition(step.Condition, ctx) {
				fmt.Printf("[-] Skipping %s (condition false)\n", step.ID)
				continue
			}
		}

		// 2. Resolve variables
		input := ResolveVars(step.Input, ctx)

		// 3. Get module
		module, ok := modules[step.Module]
		if !ok {
			return fmt.Errorf("module not found: %s", step.Module)
		}

		// 4. Execute
		result, err := module.Run(ctx, input)
		if err != nil {
			result.Error = err
			result.Success = false
		}

		// 5. Store result
		ctx.Results[step.ID] = result
	}

	return nil
}

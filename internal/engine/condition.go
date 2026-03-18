package engine

import "strings"

// EvaluateCondition evaluate une expression simple de condition.
// Support actuel :
//   - success(stepID)
func EvaluateCondition(cond string, ctx *Context) bool {
	if strings.HasPrefix(cond, "success(") {
		stepID := strings.TrimSuffix(strings.TrimPrefix(cond, "success("), ")")
		if res, ok := ctx.Results[stepID]; ok {
			return res.Success
		}
	}

	return false
}


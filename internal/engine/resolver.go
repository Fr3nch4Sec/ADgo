// internal/engine/resolver.go

package engine

import (
	"regexp"
	"strings"
)

func ResolveVars(input map[string]interface{}, ctx *Context) map[string]interface{} {
	resolved := make(map[string]interface{})

	re := regexp.MustCompile(`\{\{(.+?)\}\}`)

	for k, v := range input {
		strVal, ok := v.(string)
		if !ok {
			resolved[k] = v
			continue
		}

		match := re.FindStringSubmatch(strVal)
		if len(match) == 2 {
			parts := strings.Split(match[1], ".")

			if len(parts) == 2 {
				stepID := parts[0]
				field := parts[1]

				if res, exists := ctx.Results[stepID]; exists {
					resolved[k] = res.Data[field]
					continue
				}
			}
		}

		resolved[k] = v
	}

	return resolved
}

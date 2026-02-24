package utils

import (
	"strconv"
	"strings"
)

func ParsePortRange(r string) (int, int) {
	parts := strings.Split(r, "-")
	start, _ := strconv.Atoi(parts[0])
	end := start
	if len(parts) > 1 {
		end, _ = strconv.Atoi(parts[1])
	}
	return start, end
}

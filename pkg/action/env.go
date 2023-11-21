package action

import (
	"os/exec"
	"strings"
)

type RuntimeInfos struct {
	Version string
	Os      string
	Arch    string
}

// ReadRuntimeInfoFromEnv using go env this ensures the real information are used and no compile time versions
func ReadRuntimeInfoFromEnv() *RuntimeInfos {
	cmd := exec.Command("go", "env")
	out, _ := cmd.Output()

	info := RuntimeInfos{Version: "Unknown", Os: "Unknown", Arch: "Unknown"}

	envs := strings.Split(string(out), "\n")

	for _, env := range envs {

		if strings.Contains(env, "GOARCH") {
			keyVal := strings.SplitAfter(env, "=")
			info.Arch = strings.Trim(strings.Trim(keyVal[1], "\""), "'")
		}

		if strings.Contains(env, "GOVERSION") {
			keyVal := strings.SplitAfter(env, "=")
			info.Version = strings.Trim(strings.Trim(keyVal[1], "\""), "'")
		}

		if strings.Contains(env, "GOOS") {
			keyVal := strings.SplitAfter(env, "=")
			info.Os = strings.Trim(strings.Trim(keyVal[1], "\""), "'")
		}

	}

	return &info
}

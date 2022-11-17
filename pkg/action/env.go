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

func ReadRuntimeInfoFromEnv() (*RuntimeInfos, error) {
	cmd := exec.Command("go", "env")
	out, err := cmd.Output()

	if err != nil {
		return nil, err
	}

	info := RuntimeInfos{}

	envs := strings.Split(string(out), "\n")

	for _, env := range envs {

		if strings.Contains(env, "GOARCH") {
			keyVal := strings.SplitAfter(env, "=")
			info.Arch = strings.Trim(keyVal[1], "\"")
		}

		if strings.Contains(env, "GOVERSION") {
			keyVal := strings.SplitAfter(env, "=")
			info.Version = strings.Trim(keyVal[1], "\"")
		}

		if strings.Contains(env, "GOOS") {
			keyVal := strings.SplitAfter(env, "=")
			info.Os = strings.Trim(keyVal[1], "\"")
		}

	}

	return &info, nil
}

package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

const (
	DockerEnv = "DOCKER_WD"
	GithubEnv = "GITHUB_WD"
)

type cmdArgs struct {
	githubWorkspace       string
	inputWorkingDirectory string
}

func main() {
	var args cmdArgs

	flag.StringVar(&args.githubWorkspace, "github_workspace", "", "Github Workspace")
	flag.StringVar(&args.inputWorkingDirectory, "input_working_directory", "", "Input Working Directory")

	flag.Parse()

	if err := cmd(args); err != nil {
		log.Fatal(err)
	}
}

func cmd(args cmdArgs) error {
	if err := args.validate(); err != nil {
		return err
	}

	switch {
	case args.inputWorkingDirectory == args.githubWorkspace,
		args.inputWorkingDirectory == "":
		os.Setenv(DockerEnv, args.githubWorkspace)
		os.Setenv(GithubEnv, args.githubWorkspace)
	case strings.HasPrefix(args.inputWorkingDirectory, "/"):
		os.Setenv(DockerEnv, args.inputWorkingDirectory)
		os.Setenv(GithubEnv, fmt.Sprintf(".%s", args.inputWorkingDirectory))
	case strings.HasPrefix(args.inputWorkingDirectory, "./"):
		os.Setenv(DockerEnv, strings.TrimPrefix(args.inputWorkingDirectory, "."))
		os.Setenv(GithubEnv, args.inputWorkingDirectory)
	default:
		return fmt.Errorf(
			"input_working_directory must be empty or start with / or ./: %s",
			args.inputWorkingDirectory,
		)
	}

	log.Printf("export %s=%s", DockerEnv, os.Getenv(DockerEnv))
	log.Printf("export %s=%s", GithubEnv, os.Getenv(GithubEnv))

	return nil
}

func (ca *cmdArgs) validate() error {
	if ca.githubWorkspace == "" {
		return errors.New("github_workspace is required and can not be empty")
	}

	return nil
}

package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_cmd(t *testing.T) {
	tests := []struct {
		name              string
		args              cmdArgs
		wantErr           bool
		expectedDockerENV string
		expectedGithubENV string
	}{
		{
			name: "DOCKER_WD equals GITHUB_WD, if input_working_directory is empty",
			args: cmdArgs{
				githubWorkspace:       "/kek/lol",
				inputWorkingDirectory: "",
			},
			wantErr:           false,
			expectedDockerENV: "/kek/lol",
			expectedGithubENV: "/kek/lol",
		},
		{
			name: "DOCKER_WD equals 'input_working_directory', GITHUB_WD equals './input_working_directory': input_working_directory starts with /",
			args: cmdArgs{
				githubWorkspace:       "/kek/lol",
				inputWorkingDirectory: "/cheburek/arbidol",
			},
			wantErr:           false,
			expectedDockerENV: "/cheburek/arbidol",
			expectedGithubENV: "./cheburek/arbidol",
		},
		{
			name: "DOCKER_WD equals 'input_working_directory', GITHUB_WD equals './input_working_directory': input_working_directory starts with ./",
			args: cmdArgs{
				githubWorkspace:       "/kek/lol",
				inputWorkingDirectory: "./cheburek/arbidol",
			},
			wantErr:           false,
			expectedDockerENV: "/cheburek/arbidol",
			expectedGithubENV: "./cheburek/arbidol",
		},
		{
			name: "it returns an error, if github_workspace is empty",
			args: cmdArgs{
				githubWorkspace:       "",
				inputWorkingDirectory: "",
			},
			wantErr:           true,
			expectedDockerENV: "",
			expectedGithubENV: "",
		},
		{
			name: "it returns an error, if input_working_directory is not valid",
			args: cmdArgs{
				githubWorkspace:       "",
				inputWorkingDirectory: "",
			},
			wantErr:           true,
			expectedDockerENV: "",
			expectedGithubENV: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// cleanup results before each test.
			os.Setenv(DockerEnv, "")
			os.Setenv(GithubEnv, "")

			err := cmd(tt.args)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, os.Getenv(DockerEnv), tt.expectedDockerENV)
			require.Equal(t, os.Getenv(GithubEnv), tt.expectedGithubENV)
		})
	}
}

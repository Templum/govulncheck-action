#!/bin/bash

github_workspace=$1
input_working_directory=$2

if [ -z $github_workspace ]; then
    echo "The first argument (github.workspace) is required.";
    exit 1;
elif [[ $github_workspace = $input_working_directory || -z $input_working_directory ]]; then
    export DOCKER_WD=$github_workspace;
    export GITHUBH_WD=$github_workspace;
elif [[ $input_working_directory =~ ^/ ]]; then 
    export DOCKER_WD=$input_working_directory;
    export GITHUBH_WD=.$input_working_directory;
else 
    export DOCKER_WD=$(echo $input_working_directory |  sed 's/\.//');
    export GITHUBH_WD=$input_working_directory
fi

echo "export DOCKER_WD=$DOCKER_WD"
echo "export GITHUBH_WD=$GITHUBH_WD"

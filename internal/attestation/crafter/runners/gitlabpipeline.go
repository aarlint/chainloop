//
// Copyright 2023 The Chainloop Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runners

import (
	"os"
)

type GitlabPipeline struct{}

const GitlabPipelineID = "gitlab-pipeline"

func NewGitlabPipeline() *GitlabPipeline {
	return &GitlabPipeline{}
}

// Figure out if we are in a Github Action job or not
func (r *GitlabPipeline) CheckEnv() bool {
	for _, varName := range []string{"GITLAB_CI", "CI_JOB_URL"} {
		if os.Getenv(varName) == "" {
			return false
		}
	}

	return true
}

func (r *GitlabPipeline) ListEnvVars() []string {
	return []string{
		"GITLAB_USER_EMAIL",
		"GITLAB_USER_LOGIN",
		"CI_PROJECT_URL",
		"CI_COMMIT_SHA",
		"CI_JOB_URL",
		"CI_PIPELINE_URL",
		"CI_RUNNER_VERSION",
		"CI_RUNNER_DESCRIPTION",
		"CI_COMMIT_REF_NAME",
	}
}

func (r *GitlabPipeline) ResolveEnvVars() map[string]string {
	return resolveEnvVars(r.ListEnvVars())
}

func (r *GitlabPipeline) String() string {
	return GitlabPipelineID
}

func (r *GitlabPipeline) RunURI() (url string) {
	return os.Getenv("CI_JOB_URL")
}

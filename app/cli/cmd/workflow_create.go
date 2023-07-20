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

package cmd

import (
	"fmt"

	"github.com/chainloop-dev/chainloop/app/cli/internal/action"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

func newWorkflowCreateCmd() *cobra.Command {
	var workflowName, project, team, contract string
	var skipRACreate bool

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new workflow",
		Example: `  chainloop workflow create --name [workflowName] --project [projectName]

  # Indicate an optional team name
  chainloop workflow create --name release --project skynet --team core-cyberdyne

  # Associate an existing contract referenced by its ID
  chainloop workflow create --name release --project skynet --contract deadbeed

  # Or create a new contract by pointing to a local file or URL
  chainloop workflow create --name release --project skynet --contract ./skynet.contract.yaml
  chainloop workflow create --name release --project skynet --contract https://skynet.org/contract.yaml
  `,
		RunE: func(cmd *cobra.Command, args []string) error {
			// If it's not an UUID we try to create a contract with the potential path or url
			// Import/Create an existing contract if it's provided by it's path or URL
			// If it's provided by the UUID we skip this
			if contract != "" {
				if !isValidUUID(contract) {
					ccreateResp, err := action.NewWorkflowContractCreate(actionOpts).Run(fmt.Sprintf("%s/%s", project, workflowName), contract)
					if err != nil {
						return err
					}
					contract = ccreateResp.ID
				}
			}

			opts := &action.NewWorkflowCreateOpts{
				Name: workflowName, Team: team, Project: project, ContractID: contract,
			}

			workflow, err := action.NewWorkflowCreate(actionOpts).Run(opts)
			if err != nil {
				return err
			}

			workflowRA := &action.WorkflowItemWithRobotAccount{
				WorkflowItem: workflow,
			}

			// If the robot account creation is not skipped via --skip-robot-account-create , create a new one
			if !skipRACreate {
				ra, errRA := action.NewWorkflowRobotAccountCreate(actionOpts).Run(workflow.ID, "autogenerated")
				if errRA != nil {
					return errRA
				}
				workflowRA.RobotAccountKey = ra.Key
				workflowRA.RobotAccountID = ra.ID
			}

			// Print the workflow JSON
			if flagOutputFormat == formatJSON {
				return encodeJSON(workflowRA)
			}

			// Print the workflow table
			if err := encodeOutput([]*action.WorkflowItem{workflowRA.WorkflowItem}, WorkflowListTableOutput); err != nil {
				return err
			}

			// Print the Robot Account Token
			if workflowRA.RobotAccountID != "" {
				fmt.Printf("\nThis is automatically generated Robot Account Token (ID: %s). Save the following token since it will not printed again: \n\n %s\n\n", workflowRA.RobotAccountID, workflowRA.RobotAccountKey)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&workflowName, "name", "", "workflow name")
	err := cmd.MarkFlagRequired("name")
	cobra.CheckErr(err)

	cmd.Flags().StringVar(&project, "project", "", "project name")
	err = cmd.MarkFlagRequired("project")
	cobra.CheckErr(err)

	cmd.Flags().StringVar(&team, "team", "", "team name")
	cmd.Flags().StringVar(&contract, "contract", "", "the ID of an existing contract or the path/URL to a contract file. If not provided an empty one will be created.")

	cmd.Flags().BoolVarP(&skipRACreate, "skip-robot-account-create", "s", false, "Skip creating a Robot Account for this workflow.")

	cmd.Flags().SortFlags = false

	return cmd
}

func isValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}

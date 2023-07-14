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
	"github.com/spf13/cobra"
)

func newCASBackendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cas-backend",
		Short: "Operations on Artifact CAS backends",
	}

	cmd.AddCommand(newCASBackendListCmd(), newCASBackendAddCmd(), newCASBackendUpdateCmd())
	return cmd
}

func newCASBackendAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new Artifact CAS backend",
	}

	cmd.PersistentFlags().Bool("default", false, "set the backend as default in your organization")
	cmd.PersistentFlags().String("description", "", "descriptive information for this registration")

	cmd.AddCommand(newCASBackendAddOCICmd())
	return cmd
}

func newCASBackendUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update a CAS backend description, credentials or default status",
	}

	cmd.PersistentFlags().Bool("default", false, "set the backend as default in your organization")
	cmd.PersistentFlags().String("description", "", "descriptive information for this registration")

	cmd.AddCommand(newCASBackendUpdateOCICmd())
	return cmd
}

// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	v1 "github.com/chainloop-dev/bedrock/app/controlplane/api/controlplane/v1"
	"github.com/chainloop-dev/bedrock/app/controlplane/internal/data/ent/integration"
	"github.com/chainloop-dev/bedrock/app/controlplane/internal/data/ent/integrationattachment"
	"github.com/chainloop-dev/bedrock/app/controlplane/internal/data/ent/workflow"
	"github.com/google/uuid"
)

// IntegrationAttachment is the model entity for the IntegrationAttachment schema.
type IntegrationAttachment struct {
	config `json:"-"`
	// ID of the ent.
	ID uuid.UUID `json:"id,omitempty"`
	// CreatedAt holds the value of the "created_at" field.
	CreatedAt time.Time `json:"created_at,omitempty"`
	// Config holds the value of the "config" field.
	Config *v1.IntegrationAttachmentConfig `json:"config,omitempty"`
	// DeletedAt holds the value of the "deleted_at" field.
	DeletedAt time.Time `json:"deleted_at,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the IntegrationAttachmentQuery when eager-loading is set.
	Edges                              IntegrationAttachmentEdges `json:"edges"`
	integration_attachment_integration *uuid.UUID
	integration_attachment_workflow    *uuid.UUID
}

// IntegrationAttachmentEdges holds the relations/edges for other nodes in the graph.
type IntegrationAttachmentEdges struct {
	// Integration holds the value of the integration edge.
	Integration *Integration `json:"integration,omitempty"`
	// Workflow holds the value of the workflow edge.
	Workflow *Workflow `json:"workflow,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [2]bool
}

// IntegrationOrErr returns the Integration value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e IntegrationAttachmentEdges) IntegrationOrErr() (*Integration, error) {
	if e.loadedTypes[0] {
		if e.Integration == nil {
			// Edge was loaded but was not found.
			return nil, &NotFoundError{label: integration.Label}
		}
		return e.Integration, nil
	}
	return nil, &NotLoadedError{edge: "integration"}
}

// WorkflowOrErr returns the Workflow value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e IntegrationAttachmentEdges) WorkflowOrErr() (*Workflow, error) {
	if e.loadedTypes[1] {
		if e.Workflow == nil {
			// Edge was loaded but was not found.
			return nil, &NotFoundError{label: workflow.Label}
		}
		return e.Workflow, nil
	}
	return nil, &NotLoadedError{edge: "workflow"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*IntegrationAttachment) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case integrationattachment.FieldCreatedAt, integrationattachment.FieldDeletedAt:
			values[i] = new(sql.NullTime)
		case integrationattachment.FieldID:
			values[i] = new(uuid.UUID)
		case integrationattachment.FieldConfig:
			values[i] = new(v1.IntegrationAttachmentConfig)
		case integrationattachment.ForeignKeys[0]: // integration_attachment_integration
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		case integrationattachment.ForeignKeys[1]: // integration_attachment_workflow
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		default:
			return nil, fmt.Errorf("unexpected column %q for type IntegrationAttachment", columns[i])
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the IntegrationAttachment fields.
func (ia *IntegrationAttachment) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case integrationattachment.FieldID:
			if value, ok := values[i].(*uuid.UUID); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value != nil {
				ia.ID = *value
			}
		case integrationattachment.FieldCreatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field created_at", values[i])
			} else if value.Valid {
				ia.CreatedAt = value.Time
			}
		case integrationattachment.FieldConfig:
			if value, ok := values[i].(*v1.IntegrationAttachmentConfig); !ok {
				return fmt.Errorf("unexpected type %T for field config", values[i])
			} else if value != nil {
				ia.Config = value
			}
		case integrationattachment.FieldDeletedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field deleted_at", values[i])
			} else if value.Valid {
				ia.DeletedAt = value.Time
			}
		case integrationattachment.ForeignKeys[0]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field integration_attachment_integration", values[i])
			} else if value.Valid {
				ia.integration_attachment_integration = new(uuid.UUID)
				*ia.integration_attachment_integration = *value.S.(*uuid.UUID)
			}
		case integrationattachment.ForeignKeys[1]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field integration_attachment_workflow", values[i])
			} else if value.Valid {
				ia.integration_attachment_workflow = new(uuid.UUID)
				*ia.integration_attachment_workflow = *value.S.(*uuid.UUID)
			}
		}
	}
	return nil
}

// QueryIntegration queries the "integration" edge of the IntegrationAttachment entity.
func (ia *IntegrationAttachment) QueryIntegration() *IntegrationQuery {
	return NewIntegrationAttachmentClient(ia.config).QueryIntegration(ia)
}

// QueryWorkflow queries the "workflow" edge of the IntegrationAttachment entity.
func (ia *IntegrationAttachment) QueryWorkflow() *WorkflowQuery {
	return NewIntegrationAttachmentClient(ia.config).QueryWorkflow(ia)
}

// Update returns a builder for updating this IntegrationAttachment.
// Note that you need to call IntegrationAttachment.Unwrap() before calling this method if this IntegrationAttachment
// was returned from a transaction, and the transaction was committed or rolled back.
func (ia *IntegrationAttachment) Update() *IntegrationAttachmentUpdateOne {
	return NewIntegrationAttachmentClient(ia.config).UpdateOne(ia)
}

// Unwrap unwraps the IntegrationAttachment entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (ia *IntegrationAttachment) Unwrap() *IntegrationAttachment {
	_tx, ok := ia.config.driver.(*txDriver)
	if !ok {
		panic("ent: IntegrationAttachment is not a transactional entity")
	}
	ia.config.driver = _tx.drv
	return ia
}

// String implements the fmt.Stringer.
func (ia *IntegrationAttachment) String() string {
	var builder strings.Builder
	builder.WriteString("IntegrationAttachment(")
	builder.WriteString(fmt.Sprintf("id=%v, ", ia.ID))
	builder.WriteString("created_at=")
	builder.WriteString(ia.CreatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("config=")
	builder.WriteString(fmt.Sprintf("%v", ia.Config))
	builder.WriteString(", ")
	builder.WriteString("deleted_at=")
	builder.WriteString(ia.DeletedAt.Format(time.ANSIC))
	builder.WriteByte(')')
	return builder.String()
}

// IntegrationAttachments is a parsable slice of IntegrationAttachment.
type IntegrationAttachments []*IntegrationAttachment

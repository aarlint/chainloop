// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	v1 "github.com/chainloop-dev/bedrock/app/controlplane/api/controlplane/v1"
	"github.com/chainloop-dev/bedrock/app/controlplane/internal/data/ent/integration"
	"github.com/chainloop-dev/bedrock/app/controlplane/internal/data/ent/organization"
	"github.com/google/uuid"
)

// Integration is the model entity for the Integration schema.
type Integration struct {
	config `json:"-"`
	// ID of the ent.
	ID uuid.UUID `json:"id,omitempty"`
	// Kind holds the value of the "kind" field.
	Kind string `json:"kind,omitempty"`
	// SecretName holds the value of the "secret_name" field.
	SecretName string `json:"secret_name,omitempty"`
	// CreatedAt holds the value of the "created_at" field.
	CreatedAt time.Time `json:"created_at,omitempty"`
	// Config holds the value of the "config" field.
	Config *v1.IntegrationConfig `json:"config,omitempty"`
	// DeletedAt holds the value of the "deleted_at" field.
	DeletedAt time.Time `json:"deleted_at,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the IntegrationQuery when eager-loading is set.
	Edges                     IntegrationEdges `json:"edges"`
	organization_integrations *uuid.UUID
}

// IntegrationEdges holds the relations/edges for other nodes in the graph.
type IntegrationEdges struct {
	// Attachments holds the value of the attachments edge.
	Attachments []*IntegrationAttachment `json:"attachments,omitempty"`
	// Organization holds the value of the organization edge.
	Organization *Organization `json:"organization,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [2]bool
}

// AttachmentsOrErr returns the Attachments value or an error if the edge
// was not loaded in eager-loading.
func (e IntegrationEdges) AttachmentsOrErr() ([]*IntegrationAttachment, error) {
	if e.loadedTypes[0] {
		return e.Attachments, nil
	}
	return nil, &NotLoadedError{edge: "attachments"}
}

// OrganizationOrErr returns the Organization value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e IntegrationEdges) OrganizationOrErr() (*Organization, error) {
	if e.loadedTypes[1] {
		if e.Organization == nil {
			// Edge was loaded but was not found.
			return nil, &NotFoundError{label: organization.Label}
		}
		return e.Organization, nil
	}
	return nil, &NotLoadedError{edge: "organization"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*Integration) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case integration.FieldKind, integration.FieldSecretName:
			values[i] = new(sql.NullString)
		case integration.FieldCreatedAt, integration.FieldDeletedAt:
			values[i] = new(sql.NullTime)
		case integration.FieldID:
			values[i] = new(uuid.UUID)
		case integration.FieldConfig:
			values[i] = new(v1.IntegrationConfig)
		case integration.ForeignKeys[0]: // organization_integrations
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		default:
			return nil, fmt.Errorf("unexpected column %q for type Integration", columns[i])
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the Integration fields.
func (i *Integration) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for j := range columns {
		switch columns[j] {
		case integration.FieldID:
			if value, ok := values[j].(*uuid.UUID); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[j])
			} else if value != nil {
				i.ID = *value
			}
		case integration.FieldKind:
			if value, ok := values[j].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field kind", values[j])
			} else if value.Valid {
				i.Kind = value.String
			}
		case integration.FieldSecretName:
			if value, ok := values[j].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field secret_name", values[j])
			} else if value.Valid {
				i.SecretName = value.String
			}
		case integration.FieldCreatedAt:
			if value, ok := values[j].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field created_at", values[j])
			} else if value.Valid {
				i.CreatedAt = value.Time
			}
		case integration.FieldConfig:
			if value, ok := values[j].(*v1.IntegrationConfig); !ok {
				return fmt.Errorf("unexpected type %T for field config", values[j])
			} else if value != nil {
				i.Config = value
			}
		case integration.FieldDeletedAt:
			if value, ok := values[j].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field deleted_at", values[j])
			} else if value.Valid {
				i.DeletedAt = value.Time
			}
		case integration.ForeignKeys[0]:
			if value, ok := values[j].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field organization_integrations", values[j])
			} else if value.Valid {
				i.organization_integrations = new(uuid.UUID)
				*i.organization_integrations = *value.S.(*uuid.UUID)
			}
		}
	}
	return nil
}

// QueryAttachments queries the "attachments" edge of the Integration entity.
func (i *Integration) QueryAttachments() *IntegrationAttachmentQuery {
	return NewIntegrationClient(i.config).QueryAttachments(i)
}

// QueryOrganization queries the "organization" edge of the Integration entity.
func (i *Integration) QueryOrganization() *OrganizationQuery {
	return NewIntegrationClient(i.config).QueryOrganization(i)
}

// Update returns a builder for updating this Integration.
// Note that you need to call Integration.Unwrap() before calling this method if this Integration
// was returned from a transaction, and the transaction was committed or rolled back.
func (i *Integration) Update() *IntegrationUpdateOne {
	return NewIntegrationClient(i.config).UpdateOne(i)
}

// Unwrap unwraps the Integration entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (i *Integration) Unwrap() *Integration {
	_tx, ok := i.config.driver.(*txDriver)
	if !ok {
		panic("ent: Integration is not a transactional entity")
	}
	i.config.driver = _tx.drv
	return i
}

// String implements the fmt.Stringer.
func (i *Integration) String() string {
	var builder strings.Builder
	builder.WriteString("Integration(")
	builder.WriteString(fmt.Sprintf("id=%v, ", i.ID))
	builder.WriteString("kind=")
	builder.WriteString(i.Kind)
	builder.WriteString(", ")
	builder.WriteString("secret_name=")
	builder.WriteString(i.SecretName)
	builder.WriteString(", ")
	builder.WriteString("created_at=")
	builder.WriteString(i.CreatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("config=")
	builder.WriteString(fmt.Sprintf("%v", i.Config))
	builder.WriteString(", ")
	builder.WriteString("deleted_at=")
	builder.WriteString(i.DeletedAt.Format(time.ANSIC))
	builder.WriteByte(')')
	return builder.String()
}

// Integrations is a parsable slice of Integration.
type Integrations []*Integration

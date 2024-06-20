// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/biz"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/casbackend"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/organization"
	"github.com/google/uuid"
)

// CASBackend is the model entity for the CASBackend schema.
type CASBackend struct {
	config `json:"-"`
	// ID of the ent.
	ID uuid.UUID `json:"id,omitempty"`
	// Location holds the value of the "location" field.
	Location string `json:"location,omitempty"`
	// Name holds the value of the "name" field.
	Name string `json:"name,omitempty"`
	// Provider holds the value of the "provider" field.
	Provider biz.CASBackendProvider `json:"provider,omitempty"`
	// Description holds the value of the "description" field.
	Description string `json:"description,omitempty"`
	// SecretName holds the value of the "secret_name" field.
	SecretName string `json:"secret_name,omitempty"`
	// CreatedAt holds the value of the "created_at" field.
	CreatedAt time.Time `json:"created_at,omitempty"`
	// ValidationStatus holds the value of the "validation_status" field.
	ValidationStatus biz.CASBackendValidationStatus `json:"validation_status,omitempty"`
	// ValidatedAt holds the value of the "validated_at" field.
	ValidatedAt time.Time `json:"validated_at,omitempty"`
	// Default holds the value of the "default" field.
	Default bool `json:"default,omitempty"`
	// DeletedAt holds the value of the "deleted_at" field.
	DeletedAt time.Time `json:"deleted_at,omitempty"`
	// Fallback holds the value of the "fallback" field.
	Fallback bool `json:"fallback,omitempty"`
	// MaxBlobSizeBytes holds the value of the "max_blob_size_bytes" field.
	MaxBlobSizeBytes int64 `json:"max_blob_size_bytes,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the CASBackendQuery when eager-loading is set.
	Edges                     CASBackendEdges `json:"edges"`
	organization_cas_backends *uuid.UUID
	selectValues              sql.SelectValues
}

// CASBackendEdges holds the relations/edges for other nodes in the graph.
type CASBackendEdges struct {
	// Organization holds the value of the organization edge.
	Organization *Organization `json:"organization,omitempty"`
	// WorkflowRun holds the value of the workflow_run edge.
	WorkflowRun []*WorkflowRun `json:"workflow_run,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [2]bool
}

// OrganizationOrErr returns the Organization value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e CASBackendEdges) OrganizationOrErr() (*Organization, error) {
	if e.Organization != nil {
		return e.Organization, nil
	} else if e.loadedTypes[0] {
		return nil, &NotFoundError{label: organization.Label}
	}
	return nil, &NotLoadedError{edge: "organization"}
}

// WorkflowRunOrErr returns the WorkflowRun value or an error if the edge
// was not loaded in eager-loading.
func (e CASBackendEdges) WorkflowRunOrErr() ([]*WorkflowRun, error) {
	if e.loadedTypes[1] {
		return e.WorkflowRun, nil
	}
	return nil, &NotLoadedError{edge: "workflow_run"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*CASBackend) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case casbackend.FieldDefault, casbackend.FieldFallback:
			values[i] = new(sql.NullBool)
		case casbackend.FieldMaxBlobSizeBytes:
			values[i] = new(sql.NullInt64)
		case casbackend.FieldLocation, casbackend.FieldName, casbackend.FieldProvider, casbackend.FieldDescription, casbackend.FieldSecretName, casbackend.FieldValidationStatus:
			values[i] = new(sql.NullString)
		case casbackend.FieldCreatedAt, casbackend.FieldValidatedAt, casbackend.FieldDeletedAt:
			values[i] = new(sql.NullTime)
		case casbackend.FieldID:
			values[i] = new(uuid.UUID)
		case casbackend.ForeignKeys[0]: // organization_cas_backends
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the CASBackend fields.
func (cb *CASBackend) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case casbackend.FieldID:
			if value, ok := values[i].(*uuid.UUID); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value != nil {
				cb.ID = *value
			}
		case casbackend.FieldLocation:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field location", values[i])
			} else if value.Valid {
				cb.Location = value.String
			}
		case casbackend.FieldName:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field name", values[i])
			} else if value.Valid {
				cb.Name = value.String
			}
		case casbackend.FieldProvider:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field provider", values[i])
			} else if value.Valid {
				cb.Provider = biz.CASBackendProvider(value.String)
			}
		case casbackend.FieldDescription:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field description", values[i])
			} else if value.Valid {
				cb.Description = value.String
			}
		case casbackend.FieldSecretName:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field secret_name", values[i])
			} else if value.Valid {
				cb.SecretName = value.String
			}
		case casbackend.FieldCreatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field created_at", values[i])
			} else if value.Valid {
				cb.CreatedAt = value.Time
			}
		case casbackend.FieldValidationStatus:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field validation_status", values[i])
			} else if value.Valid {
				cb.ValidationStatus = biz.CASBackendValidationStatus(value.String)
			}
		case casbackend.FieldValidatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field validated_at", values[i])
			} else if value.Valid {
				cb.ValidatedAt = value.Time
			}
		case casbackend.FieldDefault:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field default", values[i])
			} else if value.Valid {
				cb.Default = value.Bool
			}
		case casbackend.FieldDeletedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field deleted_at", values[i])
			} else if value.Valid {
				cb.DeletedAt = value.Time
			}
		case casbackend.FieldFallback:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field fallback", values[i])
			} else if value.Valid {
				cb.Fallback = value.Bool
			}
		case casbackend.FieldMaxBlobSizeBytes:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field max_blob_size_bytes", values[i])
			} else if value.Valid {
				cb.MaxBlobSizeBytes = value.Int64
			}
		case casbackend.ForeignKeys[0]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field organization_cas_backends", values[i])
			} else if value.Valid {
				cb.organization_cas_backends = new(uuid.UUID)
				*cb.organization_cas_backends = *value.S.(*uuid.UUID)
			}
		default:
			cb.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the CASBackend.
// This includes values selected through modifiers, order, etc.
func (cb *CASBackend) Value(name string) (ent.Value, error) {
	return cb.selectValues.Get(name)
}

// QueryOrganization queries the "organization" edge of the CASBackend entity.
func (cb *CASBackend) QueryOrganization() *OrganizationQuery {
	return NewCASBackendClient(cb.config).QueryOrganization(cb)
}

// QueryWorkflowRun queries the "workflow_run" edge of the CASBackend entity.
func (cb *CASBackend) QueryWorkflowRun() *WorkflowRunQuery {
	return NewCASBackendClient(cb.config).QueryWorkflowRun(cb)
}

// Update returns a builder for updating this CASBackend.
// Note that you need to call CASBackend.Unwrap() before calling this method if this CASBackend
// was returned from a transaction, and the transaction was committed or rolled back.
func (cb *CASBackend) Update() *CASBackendUpdateOne {
	return NewCASBackendClient(cb.config).UpdateOne(cb)
}

// Unwrap unwraps the CASBackend entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (cb *CASBackend) Unwrap() *CASBackend {
	_tx, ok := cb.config.driver.(*txDriver)
	if !ok {
		panic("ent: CASBackend is not a transactional entity")
	}
	cb.config.driver = _tx.drv
	return cb
}

// String implements the fmt.Stringer.
func (cb *CASBackend) String() string {
	var builder strings.Builder
	builder.WriteString("CASBackend(")
	builder.WriteString(fmt.Sprintf("id=%v, ", cb.ID))
	builder.WriteString("location=")
	builder.WriteString(cb.Location)
	builder.WriteString(", ")
	builder.WriteString("name=")
	builder.WriteString(cb.Name)
	builder.WriteString(", ")
	builder.WriteString("provider=")
	builder.WriteString(fmt.Sprintf("%v", cb.Provider))
	builder.WriteString(", ")
	builder.WriteString("description=")
	builder.WriteString(cb.Description)
	builder.WriteString(", ")
	builder.WriteString("secret_name=")
	builder.WriteString(cb.SecretName)
	builder.WriteString(", ")
	builder.WriteString("created_at=")
	builder.WriteString(cb.CreatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("validation_status=")
	builder.WriteString(fmt.Sprintf("%v", cb.ValidationStatus))
	builder.WriteString(", ")
	builder.WriteString("validated_at=")
	builder.WriteString(cb.ValidatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("default=")
	builder.WriteString(fmt.Sprintf("%v", cb.Default))
	builder.WriteString(", ")
	builder.WriteString("deleted_at=")
	builder.WriteString(cb.DeletedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("fallback=")
	builder.WriteString(fmt.Sprintf("%v", cb.Fallback))
	builder.WriteString(", ")
	builder.WriteString("max_blob_size_bytes=")
	builder.WriteString(fmt.Sprintf("%v", cb.MaxBlobSizeBytes))
	builder.WriteByte(')')
	return builder.String()
}

// CASBackends is a parsable slice of CASBackend.
type CASBackends []*CASBackend

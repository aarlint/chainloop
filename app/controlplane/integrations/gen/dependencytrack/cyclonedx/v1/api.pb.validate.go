// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: dependencytrack/cyclonedx/v1/api.proto

package v1

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/anypb"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = anypb.Any{}
	_ = sort.Sort
)

// Validate checks the field values on RegistrationRequest with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *RegistrationRequest) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on RegistrationRequest with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// RegistrationRequestMultiError, or nil if none found.
func (m *RegistrationRequest) ValidateAll() error {
	return m.validate(true)
}

func (m *RegistrationRequest) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if m.GetConfig() == nil {
		err := RegistrationRequestValidationError{
			field:  "Config",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if all {
		switch v := interface{}(m.GetConfig()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, RegistrationRequestValidationError{
					field:  "Config",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, RegistrationRequestValidationError{
					field:  "Config",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetConfig()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return RegistrationRequestValidationError{
				field:  "Config",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if utf8.RuneCountInString(m.GetApiKey()) < 1 {
		err := RegistrationRequestValidationError{
			field:  "ApiKey",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return RegistrationRequestMultiError(errors)
	}

	return nil
}

// RegistrationRequestMultiError is an error wrapping multiple validation
// errors returned by RegistrationRequest.ValidateAll() if the designated
// constraints aren't met.
type RegistrationRequestMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m RegistrationRequestMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m RegistrationRequestMultiError) AllErrors() []error { return m }

// RegistrationRequestValidationError is the validation error returned by
// RegistrationRequest.Validate if the designated constraints aren't met.
type RegistrationRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e RegistrationRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e RegistrationRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e RegistrationRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e RegistrationRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e RegistrationRequestValidationError) ErrorName() string {
	return "RegistrationRequestValidationError"
}

// Error satisfies the builtin error interface
func (e RegistrationRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sRegistrationRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = RegistrationRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = RegistrationRequestValidationError{}

// Validate checks the field values on AttachmentRequest with the rules defined
// in the proto definition for this message. If any rules are violated, the
// first error encountered is returned, or nil if there are no violations.
func (m *AttachmentRequest) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on AttachmentRequest with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// AttachmentRequestMultiError, or nil if none found.
func (m *AttachmentRequest) ValidateAll() error {
	return m.validate(true)
}

func (m *AttachmentRequest) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if m.GetConfig() == nil {
		err := AttachmentRequestValidationError{
			field:  "Config",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if all {
		switch v := interface{}(m.GetConfig()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, AttachmentRequestValidationError{
					field:  "Config",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, AttachmentRequestValidationError{
					field:  "Config",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetConfig()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return AttachmentRequestValidationError{
				field:  "Config",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return AttachmentRequestMultiError(errors)
	}

	return nil
}

// AttachmentRequestMultiError is an error wrapping multiple validation errors
// returned by AttachmentRequest.ValidateAll() if the designated constraints
// aren't met.
type AttachmentRequestMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m AttachmentRequestMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m AttachmentRequestMultiError) AllErrors() []error { return m }

// AttachmentRequestValidationError is the validation error returned by
// AttachmentRequest.Validate if the designated constraints aren't met.
type AttachmentRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e AttachmentRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e AttachmentRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e AttachmentRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e AttachmentRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e AttachmentRequestValidationError) ErrorName() string {
	return "AttachmentRequestValidationError"
}

// Error satisfies the builtin error interface
func (e AttachmentRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sAttachmentRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = AttachmentRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = AttachmentRequestValidationError{}

// Validate checks the field values on RegistrationConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *RegistrationConfig) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on RegistrationConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// RegistrationConfigMultiError, or nil if none found.
func (m *RegistrationConfig) ValidateAll() error {
	return m.validate(true)
}

func (m *RegistrationConfig) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if utf8.RuneCountInString(m.GetDomain()) < 1 {
		err := RegistrationConfigValidationError{
			field:  "Domain",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	// no validation rules for AllowAutoCreate

	if len(errors) > 0 {
		return RegistrationConfigMultiError(errors)
	}

	return nil
}

// RegistrationConfigMultiError is an error wrapping multiple validation errors
// returned by RegistrationConfig.ValidateAll() if the designated constraints
// aren't met.
type RegistrationConfigMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m RegistrationConfigMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m RegistrationConfigMultiError) AllErrors() []error { return m }

// RegistrationConfigValidationError is the validation error returned by
// RegistrationConfig.Validate if the designated constraints aren't met.
type RegistrationConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e RegistrationConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e RegistrationConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e RegistrationConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e RegistrationConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e RegistrationConfigValidationError) ErrorName() string {
	return "RegistrationConfigValidationError"
}

// Error satisfies the builtin error interface
func (e RegistrationConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sRegistrationConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = RegistrationConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = RegistrationConfigValidationError{}

// Validate checks the field values on AttachmentConfig with the rules defined
// in the proto definition for this message. If any rules are violated, the
// first error encountered is returned, or nil if there are no violations.
func (m *AttachmentConfig) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on AttachmentConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// AttachmentConfigMultiError, or nil if none found.
func (m *AttachmentConfig) ValidateAll() error {
	return m.validate(true)
}

func (m *AttachmentConfig) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	oneofProjectPresent := false
	switch v := m.Project.(type) {
	case *AttachmentConfig_ProjectId:
		if v == nil {
			err := AttachmentConfigValidationError{
				field:  "Project",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}
		oneofProjectPresent = true
		// no validation rules for ProjectId
	case *AttachmentConfig_ProjectName:
		if v == nil {
			err := AttachmentConfigValidationError{
				field:  "Project",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}
		oneofProjectPresent = true
		// no validation rules for ProjectName
	default:
		_ = v // ensures v is used
	}
	if !oneofProjectPresent {
		err := AttachmentConfigValidationError{
			field:  "Project",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return AttachmentConfigMultiError(errors)
	}

	return nil
}

// AttachmentConfigMultiError is an error wrapping multiple validation errors
// returned by AttachmentConfig.ValidateAll() if the designated constraints
// aren't met.
type AttachmentConfigMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m AttachmentConfigMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m AttachmentConfigMultiError) AllErrors() []error { return m }

// AttachmentConfigValidationError is the validation error returned by
// AttachmentConfig.Validate if the designated constraints aren't met.
type AttachmentConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e AttachmentConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e AttachmentConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e AttachmentConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e AttachmentConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e AttachmentConfigValidationError) ErrorName() string { return "AttachmentConfigValidationError" }

// Error satisfies the builtin error interface
func (e AttachmentConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sAttachmentConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = AttachmentConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = AttachmentConfigValidationError{}
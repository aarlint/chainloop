// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: controlplane/v1/auth.proto

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

// Validate checks the field values on AuthServiceDeleteAccountRequest with the
// rules defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *AuthServiceDeleteAccountRequest) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on AuthServiceDeleteAccountRequest with
// the rules defined in the proto definition for this message. If any rules
// are violated, the result is a list of violation errors wrapped in
// AuthServiceDeleteAccountRequestMultiError, or nil if none found.
func (m *AuthServiceDeleteAccountRequest) ValidateAll() error {
	return m.validate(true)
}

func (m *AuthServiceDeleteAccountRequest) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if len(errors) > 0 {
		return AuthServiceDeleteAccountRequestMultiError(errors)
	}

	return nil
}

// AuthServiceDeleteAccountRequestMultiError is an error wrapping multiple
// validation errors returned by AuthServiceDeleteAccountRequest.ValidateAll()
// if the designated constraints aren't met.
type AuthServiceDeleteAccountRequestMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m AuthServiceDeleteAccountRequestMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m AuthServiceDeleteAccountRequestMultiError) AllErrors() []error { return m }

// AuthServiceDeleteAccountRequestValidationError is the validation error
// returned by AuthServiceDeleteAccountRequest.Validate if the designated
// constraints aren't met.
type AuthServiceDeleteAccountRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e AuthServiceDeleteAccountRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e AuthServiceDeleteAccountRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e AuthServiceDeleteAccountRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e AuthServiceDeleteAccountRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e AuthServiceDeleteAccountRequestValidationError) ErrorName() string {
	return "AuthServiceDeleteAccountRequestValidationError"
}

// Error satisfies the builtin error interface
func (e AuthServiceDeleteAccountRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sAuthServiceDeleteAccountRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = AuthServiceDeleteAccountRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = AuthServiceDeleteAccountRequestValidationError{}

// Validate checks the field values on AuthServiceDeleteAccountResponse with
// the rules defined in the proto definition for this message. If any rules
// are violated, the first error encountered is returned, or nil if there are
// no violations.
func (m *AuthServiceDeleteAccountResponse) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on AuthServiceDeleteAccountResponse with
// the rules defined in the proto definition for this message. If any rules
// are violated, the result is a list of violation errors wrapped in
// AuthServiceDeleteAccountResponseMultiError, or nil if none found.
func (m *AuthServiceDeleteAccountResponse) ValidateAll() error {
	return m.validate(true)
}

func (m *AuthServiceDeleteAccountResponse) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if len(errors) > 0 {
		return AuthServiceDeleteAccountResponseMultiError(errors)
	}

	return nil
}

// AuthServiceDeleteAccountResponseMultiError is an error wrapping multiple
// validation errors returned by
// AuthServiceDeleteAccountResponse.ValidateAll() if the designated
// constraints aren't met.
type AuthServiceDeleteAccountResponseMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m AuthServiceDeleteAccountResponseMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m AuthServiceDeleteAccountResponseMultiError) AllErrors() []error { return m }

// AuthServiceDeleteAccountResponseValidationError is the validation error
// returned by AuthServiceDeleteAccountResponse.Validate if the designated
// constraints aren't met.
type AuthServiceDeleteAccountResponseValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e AuthServiceDeleteAccountResponseValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e AuthServiceDeleteAccountResponseValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e AuthServiceDeleteAccountResponseValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e AuthServiceDeleteAccountResponseValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e AuthServiceDeleteAccountResponseValidationError) ErrorName() string {
	return "AuthServiceDeleteAccountResponseValidationError"
}

// Error satisfies the builtin error interface
func (e AuthServiceDeleteAccountResponseValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sAuthServiceDeleteAccountResponse.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = AuthServiceDeleteAccountResponseValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = AuthServiceDeleteAccountResponseValidationError{}

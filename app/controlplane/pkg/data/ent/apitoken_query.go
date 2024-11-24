// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/apitoken"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/organization"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/predicate"
	"github.com/google/uuid"
)

// APITokenQuery is the builder for querying APIToken entities.
type APITokenQuery struct {
	config
	ctx              *QueryContext
	order            []apitoken.OrderOption
	inters           []Interceptor
	predicates       []predicate.APIToken
	withOrganization *OrganizationQuery
	modifiers        []func(*sql.Selector)
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the APITokenQuery builder.
func (atq *APITokenQuery) Where(ps ...predicate.APIToken) *APITokenQuery {
	atq.predicates = append(atq.predicates, ps...)
	return atq
}

// Limit the number of records to be returned by this query.
func (atq *APITokenQuery) Limit(limit int) *APITokenQuery {
	atq.ctx.Limit = &limit
	return atq
}

// Offset to start from.
func (atq *APITokenQuery) Offset(offset int) *APITokenQuery {
	atq.ctx.Offset = &offset
	return atq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (atq *APITokenQuery) Unique(unique bool) *APITokenQuery {
	atq.ctx.Unique = &unique
	return atq
}

// Order specifies how the records should be ordered.
func (atq *APITokenQuery) Order(o ...apitoken.OrderOption) *APITokenQuery {
	atq.order = append(atq.order, o...)
	return atq
}

// QueryOrganization chains the current query on the "organization" edge.
func (atq *APITokenQuery) QueryOrganization() *OrganizationQuery {
	query := (&OrganizationClient{config: atq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := atq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := atq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(apitoken.Table, apitoken.FieldID, selector),
			sqlgraph.To(organization.Table, organization.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, apitoken.OrganizationTable, apitoken.OrganizationColumn),
		)
		fromU = sqlgraph.SetNeighbors(atq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first APIToken entity from the query.
// Returns a *NotFoundError when no APIToken was found.
func (atq *APITokenQuery) First(ctx context.Context) (*APIToken, error) {
	nodes, err := atq.Limit(1).All(setContextOp(ctx, atq.ctx, ent.OpQueryFirst))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{apitoken.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (atq *APITokenQuery) FirstX(ctx context.Context) *APIToken {
	node, err := atq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first APIToken ID from the query.
// Returns a *NotFoundError when no APIToken ID was found.
func (atq *APITokenQuery) FirstID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = atq.Limit(1).IDs(setContextOp(ctx, atq.ctx, ent.OpQueryFirstID)); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{apitoken.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (atq *APITokenQuery) FirstIDX(ctx context.Context) uuid.UUID {
	id, err := atq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single APIToken entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one APIToken entity is found.
// Returns a *NotFoundError when no APIToken entities are found.
func (atq *APITokenQuery) Only(ctx context.Context) (*APIToken, error) {
	nodes, err := atq.Limit(2).All(setContextOp(ctx, atq.ctx, ent.OpQueryOnly))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{apitoken.Label}
	default:
		return nil, &NotSingularError{apitoken.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (atq *APITokenQuery) OnlyX(ctx context.Context) *APIToken {
	node, err := atq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only APIToken ID in the query.
// Returns a *NotSingularError when more than one APIToken ID is found.
// Returns a *NotFoundError when no entities are found.
func (atq *APITokenQuery) OnlyID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = atq.Limit(2).IDs(setContextOp(ctx, atq.ctx, ent.OpQueryOnlyID)); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{apitoken.Label}
	default:
		err = &NotSingularError{apitoken.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (atq *APITokenQuery) OnlyIDX(ctx context.Context) uuid.UUID {
	id, err := atq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of APITokens.
func (atq *APITokenQuery) All(ctx context.Context) ([]*APIToken, error) {
	ctx = setContextOp(ctx, atq.ctx, ent.OpQueryAll)
	if err := atq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*APIToken, *APITokenQuery]()
	return withInterceptors[[]*APIToken](ctx, atq, qr, atq.inters)
}

// AllX is like All, but panics if an error occurs.
func (atq *APITokenQuery) AllX(ctx context.Context) []*APIToken {
	nodes, err := atq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of APIToken IDs.
func (atq *APITokenQuery) IDs(ctx context.Context) (ids []uuid.UUID, err error) {
	if atq.ctx.Unique == nil && atq.path != nil {
		atq.Unique(true)
	}
	ctx = setContextOp(ctx, atq.ctx, ent.OpQueryIDs)
	if err = atq.Select(apitoken.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (atq *APITokenQuery) IDsX(ctx context.Context) []uuid.UUID {
	ids, err := atq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (atq *APITokenQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, atq.ctx, ent.OpQueryCount)
	if err := atq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, atq, querierCount[*APITokenQuery](), atq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (atq *APITokenQuery) CountX(ctx context.Context) int {
	count, err := atq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (atq *APITokenQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, atq.ctx, ent.OpQueryExist)
	switch _, err := atq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (atq *APITokenQuery) ExistX(ctx context.Context) bool {
	exist, err := atq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the APITokenQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (atq *APITokenQuery) Clone() *APITokenQuery {
	if atq == nil {
		return nil
	}
	return &APITokenQuery{
		config:           atq.config,
		ctx:              atq.ctx.Clone(),
		order:            append([]apitoken.OrderOption{}, atq.order...),
		inters:           append([]Interceptor{}, atq.inters...),
		predicates:       append([]predicate.APIToken{}, atq.predicates...),
		withOrganization: atq.withOrganization.Clone(),
		// clone intermediate query.
		sql:       atq.sql.Clone(),
		path:      atq.path,
		modifiers: append([]func(*sql.Selector){}, atq.modifiers...),
	}
}

// WithOrganization tells the query-builder to eager-load the nodes that are connected to
// the "organization" edge. The optional arguments are used to configure the query builder of the edge.
func (atq *APITokenQuery) WithOrganization(opts ...func(*OrganizationQuery)) *APITokenQuery {
	query := (&OrganizationClient{config: atq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	atq.withOrganization = query
	return atq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		Name string `json:"name,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.APIToken.Query().
//		GroupBy(apitoken.FieldName).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (atq *APITokenQuery) GroupBy(field string, fields ...string) *APITokenGroupBy {
	atq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &APITokenGroupBy{build: atq}
	grbuild.flds = &atq.ctx.Fields
	grbuild.label = apitoken.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		Name string `json:"name,omitempty"`
//	}
//
//	client.APIToken.Query().
//		Select(apitoken.FieldName).
//		Scan(ctx, &v)
func (atq *APITokenQuery) Select(fields ...string) *APITokenSelect {
	atq.ctx.Fields = append(atq.ctx.Fields, fields...)
	sbuild := &APITokenSelect{APITokenQuery: atq}
	sbuild.label = apitoken.Label
	sbuild.flds, sbuild.scan = &atq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a APITokenSelect configured with the given aggregations.
func (atq *APITokenQuery) Aggregate(fns ...AggregateFunc) *APITokenSelect {
	return atq.Select().Aggregate(fns...)
}

func (atq *APITokenQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range atq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, atq); err != nil {
				return err
			}
		}
	}
	for _, f := range atq.ctx.Fields {
		if !apitoken.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if atq.path != nil {
		prev, err := atq.path(ctx)
		if err != nil {
			return err
		}
		atq.sql = prev
	}
	return nil
}

func (atq *APITokenQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*APIToken, error) {
	var (
		nodes       = []*APIToken{}
		_spec       = atq.querySpec()
		loadedTypes = [1]bool{
			atq.withOrganization != nil,
		}
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*APIToken).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &APIToken{config: atq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	if len(atq.modifiers) > 0 {
		_spec.Modifiers = atq.modifiers
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, atq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := atq.withOrganization; query != nil {
		if err := atq.loadOrganization(ctx, query, nodes, nil,
			func(n *APIToken, e *Organization) { n.Edges.Organization = e }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (atq *APITokenQuery) loadOrganization(ctx context.Context, query *OrganizationQuery, nodes []*APIToken, init func(*APIToken), assign func(*APIToken, *Organization)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*APIToken)
	for i := range nodes {
		fk := nodes[i].OrganizationID
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(organization.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "organization_id" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (atq *APITokenQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := atq.querySpec()
	if len(atq.modifiers) > 0 {
		_spec.Modifiers = atq.modifiers
	}
	_spec.Node.Columns = atq.ctx.Fields
	if len(atq.ctx.Fields) > 0 {
		_spec.Unique = atq.ctx.Unique != nil && *atq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, atq.driver, _spec)
}

func (atq *APITokenQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(apitoken.Table, apitoken.Columns, sqlgraph.NewFieldSpec(apitoken.FieldID, field.TypeUUID))
	_spec.From = atq.sql
	if unique := atq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if atq.path != nil {
		_spec.Unique = true
	}
	if fields := atq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, apitoken.FieldID)
		for i := range fields {
			if fields[i] != apitoken.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
		if atq.withOrganization != nil {
			_spec.Node.AddColumnOnce(apitoken.FieldOrganizationID)
		}
	}
	if ps := atq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := atq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := atq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := atq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (atq *APITokenQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(atq.driver.Dialect())
	t1 := builder.Table(apitoken.Table)
	columns := atq.ctx.Fields
	if len(columns) == 0 {
		columns = apitoken.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if atq.sql != nil {
		selector = atq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if atq.ctx.Unique != nil && *atq.ctx.Unique {
		selector.Distinct()
	}
	for _, m := range atq.modifiers {
		m(selector)
	}
	for _, p := range atq.predicates {
		p(selector)
	}
	for _, p := range atq.order {
		p(selector)
	}
	if offset := atq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := atq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// ForUpdate locks the selected rows against concurrent updates, and prevent them from being
// updated, deleted or "selected ... for update" by other sessions, until the transaction is
// either committed or rolled-back.
func (atq *APITokenQuery) ForUpdate(opts ...sql.LockOption) *APITokenQuery {
	if atq.driver.Dialect() == dialect.Postgres {
		atq.Unique(false)
	}
	atq.modifiers = append(atq.modifiers, func(s *sql.Selector) {
		s.ForUpdate(opts...)
	})
	return atq
}

// ForShare behaves similarly to ForUpdate, except that it acquires a shared mode lock
// on any rows that are read. Other sessions can read the rows, but cannot modify them
// until your transaction commits.
func (atq *APITokenQuery) ForShare(opts ...sql.LockOption) *APITokenQuery {
	if atq.driver.Dialect() == dialect.Postgres {
		atq.Unique(false)
	}
	atq.modifiers = append(atq.modifiers, func(s *sql.Selector) {
		s.ForShare(opts...)
	})
	return atq
}

// Modify adds a query modifier for attaching custom logic to queries.
func (atq *APITokenQuery) Modify(modifiers ...func(s *sql.Selector)) *APITokenSelect {
	atq.modifiers = append(atq.modifiers, modifiers...)
	return atq.Select()
}

// APITokenGroupBy is the group-by builder for APIToken entities.
type APITokenGroupBy struct {
	selector
	build *APITokenQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (atgb *APITokenGroupBy) Aggregate(fns ...AggregateFunc) *APITokenGroupBy {
	atgb.fns = append(atgb.fns, fns...)
	return atgb
}

// Scan applies the selector query and scans the result into the given value.
func (atgb *APITokenGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, atgb.build.ctx, ent.OpQueryGroupBy)
	if err := atgb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*APITokenQuery, *APITokenGroupBy](ctx, atgb.build, atgb, atgb.build.inters, v)
}

func (atgb *APITokenGroupBy) sqlScan(ctx context.Context, root *APITokenQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(atgb.fns))
	for _, fn := range atgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*atgb.flds)+len(atgb.fns))
		for _, f := range *atgb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*atgb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := atgb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// APITokenSelect is the builder for selecting fields of APIToken entities.
type APITokenSelect struct {
	*APITokenQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (ats *APITokenSelect) Aggregate(fns ...AggregateFunc) *APITokenSelect {
	ats.fns = append(ats.fns, fns...)
	return ats
}

// Scan applies the selector query and scans the result into the given value.
func (ats *APITokenSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, ats.ctx, ent.OpQuerySelect)
	if err := ats.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*APITokenQuery, *APITokenSelect](ctx, ats.APITokenQuery, ats, ats.inters, v)
}

func (ats *APITokenSelect) sqlScan(ctx context.Context, root *APITokenQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(ats.fns))
	for _, fn := range ats.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*ats.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := ats.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// Modify adds a query modifier for attaching custom logic to queries.
func (ats *APITokenSelect) Modify(modifiers ...func(s *sql.Selector)) *APITokenSelect {
	ats.modifiers = append(ats.modifiers, modifiers...)
	return ats
}

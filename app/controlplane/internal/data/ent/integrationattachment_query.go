// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/chainloop-dev/bedrock/app/controlplane/internal/data/ent/integration"
	"github.com/chainloop-dev/bedrock/app/controlplane/internal/data/ent/integrationattachment"
	"github.com/chainloop-dev/bedrock/app/controlplane/internal/data/ent/predicate"
	"github.com/chainloop-dev/bedrock/app/controlplane/internal/data/ent/workflow"
	"github.com/google/uuid"
)

// IntegrationAttachmentQuery is the builder for querying IntegrationAttachment entities.
type IntegrationAttachmentQuery struct {
	config
	ctx             *QueryContext
	order           []OrderFunc
	inters          []Interceptor
	predicates      []predicate.IntegrationAttachment
	withIntegration *IntegrationQuery
	withWorkflow    *WorkflowQuery
	withFKs         bool
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the IntegrationAttachmentQuery builder.
func (iaq *IntegrationAttachmentQuery) Where(ps ...predicate.IntegrationAttachment) *IntegrationAttachmentQuery {
	iaq.predicates = append(iaq.predicates, ps...)
	return iaq
}

// Limit the number of records to be returned by this query.
func (iaq *IntegrationAttachmentQuery) Limit(limit int) *IntegrationAttachmentQuery {
	iaq.ctx.Limit = &limit
	return iaq
}

// Offset to start from.
func (iaq *IntegrationAttachmentQuery) Offset(offset int) *IntegrationAttachmentQuery {
	iaq.ctx.Offset = &offset
	return iaq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (iaq *IntegrationAttachmentQuery) Unique(unique bool) *IntegrationAttachmentQuery {
	iaq.ctx.Unique = &unique
	return iaq
}

// Order specifies how the records should be ordered.
func (iaq *IntegrationAttachmentQuery) Order(o ...OrderFunc) *IntegrationAttachmentQuery {
	iaq.order = append(iaq.order, o...)
	return iaq
}

// QueryIntegration chains the current query on the "integration" edge.
func (iaq *IntegrationAttachmentQuery) QueryIntegration() *IntegrationQuery {
	query := (&IntegrationClient{config: iaq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := iaq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := iaq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(integrationattachment.Table, integrationattachment.FieldID, selector),
			sqlgraph.To(integration.Table, integration.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, integrationattachment.IntegrationTable, integrationattachment.IntegrationColumn),
		)
		fromU = sqlgraph.SetNeighbors(iaq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryWorkflow chains the current query on the "workflow" edge.
func (iaq *IntegrationAttachmentQuery) QueryWorkflow() *WorkflowQuery {
	query := (&WorkflowClient{config: iaq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := iaq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := iaq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(integrationattachment.Table, integrationattachment.FieldID, selector),
			sqlgraph.To(workflow.Table, workflow.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, integrationattachment.WorkflowTable, integrationattachment.WorkflowColumn),
		)
		fromU = sqlgraph.SetNeighbors(iaq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first IntegrationAttachment entity from the query.
// Returns a *NotFoundError when no IntegrationAttachment was found.
func (iaq *IntegrationAttachmentQuery) First(ctx context.Context) (*IntegrationAttachment, error) {
	nodes, err := iaq.Limit(1).All(setContextOp(ctx, iaq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{integrationattachment.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (iaq *IntegrationAttachmentQuery) FirstX(ctx context.Context) *IntegrationAttachment {
	node, err := iaq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first IntegrationAttachment ID from the query.
// Returns a *NotFoundError when no IntegrationAttachment ID was found.
func (iaq *IntegrationAttachmentQuery) FirstID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = iaq.Limit(1).IDs(setContextOp(ctx, iaq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{integrationattachment.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (iaq *IntegrationAttachmentQuery) FirstIDX(ctx context.Context) uuid.UUID {
	id, err := iaq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single IntegrationAttachment entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one IntegrationAttachment entity is found.
// Returns a *NotFoundError when no IntegrationAttachment entities are found.
func (iaq *IntegrationAttachmentQuery) Only(ctx context.Context) (*IntegrationAttachment, error) {
	nodes, err := iaq.Limit(2).All(setContextOp(ctx, iaq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{integrationattachment.Label}
	default:
		return nil, &NotSingularError{integrationattachment.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (iaq *IntegrationAttachmentQuery) OnlyX(ctx context.Context) *IntegrationAttachment {
	node, err := iaq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only IntegrationAttachment ID in the query.
// Returns a *NotSingularError when more than one IntegrationAttachment ID is found.
// Returns a *NotFoundError when no entities are found.
func (iaq *IntegrationAttachmentQuery) OnlyID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = iaq.Limit(2).IDs(setContextOp(ctx, iaq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{integrationattachment.Label}
	default:
		err = &NotSingularError{integrationattachment.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (iaq *IntegrationAttachmentQuery) OnlyIDX(ctx context.Context) uuid.UUID {
	id, err := iaq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of IntegrationAttachments.
func (iaq *IntegrationAttachmentQuery) All(ctx context.Context) ([]*IntegrationAttachment, error) {
	ctx = setContextOp(ctx, iaq.ctx, "All")
	if err := iaq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*IntegrationAttachment, *IntegrationAttachmentQuery]()
	return withInterceptors[[]*IntegrationAttachment](ctx, iaq, qr, iaq.inters)
}

// AllX is like All, but panics if an error occurs.
func (iaq *IntegrationAttachmentQuery) AllX(ctx context.Context) []*IntegrationAttachment {
	nodes, err := iaq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of IntegrationAttachment IDs.
func (iaq *IntegrationAttachmentQuery) IDs(ctx context.Context) (ids []uuid.UUID, err error) {
	if iaq.ctx.Unique == nil && iaq.path != nil {
		iaq.Unique(true)
	}
	ctx = setContextOp(ctx, iaq.ctx, "IDs")
	if err = iaq.Select(integrationattachment.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (iaq *IntegrationAttachmentQuery) IDsX(ctx context.Context) []uuid.UUID {
	ids, err := iaq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (iaq *IntegrationAttachmentQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, iaq.ctx, "Count")
	if err := iaq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, iaq, querierCount[*IntegrationAttachmentQuery](), iaq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (iaq *IntegrationAttachmentQuery) CountX(ctx context.Context) int {
	count, err := iaq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (iaq *IntegrationAttachmentQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, iaq.ctx, "Exist")
	switch _, err := iaq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (iaq *IntegrationAttachmentQuery) ExistX(ctx context.Context) bool {
	exist, err := iaq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the IntegrationAttachmentQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (iaq *IntegrationAttachmentQuery) Clone() *IntegrationAttachmentQuery {
	if iaq == nil {
		return nil
	}
	return &IntegrationAttachmentQuery{
		config:          iaq.config,
		ctx:             iaq.ctx.Clone(),
		order:           append([]OrderFunc{}, iaq.order...),
		inters:          append([]Interceptor{}, iaq.inters...),
		predicates:      append([]predicate.IntegrationAttachment{}, iaq.predicates...),
		withIntegration: iaq.withIntegration.Clone(),
		withWorkflow:    iaq.withWorkflow.Clone(),
		// clone intermediate query.
		sql:  iaq.sql.Clone(),
		path: iaq.path,
	}
}

// WithIntegration tells the query-builder to eager-load the nodes that are connected to
// the "integration" edge. The optional arguments are used to configure the query builder of the edge.
func (iaq *IntegrationAttachmentQuery) WithIntegration(opts ...func(*IntegrationQuery)) *IntegrationAttachmentQuery {
	query := (&IntegrationClient{config: iaq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	iaq.withIntegration = query
	return iaq
}

// WithWorkflow tells the query-builder to eager-load the nodes that are connected to
// the "workflow" edge. The optional arguments are used to configure the query builder of the edge.
func (iaq *IntegrationAttachmentQuery) WithWorkflow(opts ...func(*WorkflowQuery)) *IntegrationAttachmentQuery {
	query := (&WorkflowClient{config: iaq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	iaq.withWorkflow = query
	return iaq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		CreatedAt time.Time `json:"created_at,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.IntegrationAttachment.Query().
//		GroupBy(integrationattachment.FieldCreatedAt).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (iaq *IntegrationAttachmentQuery) GroupBy(field string, fields ...string) *IntegrationAttachmentGroupBy {
	iaq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &IntegrationAttachmentGroupBy{build: iaq}
	grbuild.flds = &iaq.ctx.Fields
	grbuild.label = integrationattachment.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		CreatedAt time.Time `json:"created_at,omitempty"`
//	}
//
//	client.IntegrationAttachment.Query().
//		Select(integrationattachment.FieldCreatedAt).
//		Scan(ctx, &v)
func (iaq *IntegrationAttachmentQuery) Select(fields ...string) *IntegrationAttachmentSelect {
	iaq.ctx.Fields = append(iaq.ctx.Fields, fields...)
	sbuild := &IntegrationAttachmentSelect{IntegrationAttachmentQuery: iaq}
	sbuild.label = integrationattachment.Label
	sbuild.flds, sbuild.scan = &iaq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a IntegrationAttachmentSelect configured with the given aggregations.
func (iaq *IntegrationAttachmentQuery) Aggregate(fns ...AggregateFunc) *IntegrationAttachmentSelect {
	return iaq.Select().Aggregate(fns...)
}

func (iaq *IntegrationAttachmentQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range iaq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, iaq); err != nil {
				return err
			}
		}
	}
	for _, f := range iaq.ctx.Fields {
		if !integrationattachment.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if iaq.path != nil {
		prev, err := iaq.path(ctx)
		if err != nil {
			return err
		}
		iaq.sql = prev
	}
	return nil
}

func (iaq *IntegrationAttachmentQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*IntegrationAttachment, error) {
	var (
		nodes       = []*IntegrationAttachment{}
		withFKs     = iaq.withFKs
		_spec       = iaq.querySpec()
		loadedTypes = [2]bool{
			iaq.withIntegration != nil,
			iaq.withWorkflow != nil,
		}
	)
	if iaq.withIntegration != nil || iaq.withWorkflow != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, integrationattachment.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*IntegrationAttachment).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &IntegrationAttachment{config: iaq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, iaq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := iaq.withIntegration; query != nil {
		if err := iaq.loadIntegration(ctx, query, nodes, nil,
			func(n *IntegrationAttachment, e *Integration) { n.Edges.Integration = e }); err != nil {
			return nil, err
		}
	}
	if query := iaq.withWorkflow; query != nil {
		if err := iaq.loadWorkflow(ctx, query, nodes, nil,
			func(n *IntegrationAttachment, e *Workflow) { n.Edges.Workflow = e }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (iaq *IntegrationAttachmentQuery) loadIntegration(ctx context.Context, query *IntegrationQuery, nodes []*IntegrationAttachment, init func(*IntegrationAttachment), assign func(*IntegrationAttachment, *Integration)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*IntegrationAttachment)
	for i := range nodes {
		if nodes[i].integration_attachment_integration == nil {
			continue
		}
		fk := *nodes[i].integration_attachment_integration
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(integration.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "integration_attachment_integration" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (iaq *IntegrationAttachmentQuery) loadWorkflow(ctx context.Context, query *WorkflowQuery, nodes []*IntegrationAttachment, init func(*IntegrationAttachment), assign func(*IntegrationAttachment, *Workflow)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*IntegrationAttachment)
	for i := range nodes {
		if nodes[i].integration_attachment_workflow == nil {
			continue
		}
		fk := *nodes[i].integration_attachment_workflow
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(workflow.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "integration_attachment_workflow" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (iaq *IntegrationAttachmentQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := iaq.querySpec()
	_spec.Node.Columns = iaq.ctx.Fields
	if len(iaq.ctx.Fields) > 0 {
		_spec.Unique = iaq.ctx.Unique != nil && *iaq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, iaq.driver, _spec)
}

func (iaq *IntegrationAttachmentQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(integrationattachment.Table, integrationattachment.Columns, sqlgraph.NewFieldSpec(integrationattachment.FieldID, field.TypeUUID))
	_spec.From = iaq.sql
	if unique := iaq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if iaq.path != nil {
		_spec.Unique = true
	}
	if fields := iaq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, integrationattachment.FieldID)
		for i := range fields {
			if fields[i] != integrationattachment.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := iaq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := iaq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := iaq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := iaq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (iaq *IntegrationAttachmentQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(iaq.driver.Dialect())
	t1 := builder.Table(integrationattachment.Table)
	columns := iaq.ctx.Fields
	if len(columns) == 0 {
		columns = integrationattachment.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if iaq.sql != nil {
		selector = iaq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if iaq.ctx.Unique != nil && *iaq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range iaq.predicates {
		p(selector)
	}
	for _, p := range iaq.order {
		p(selector)
	}
	if offset := iaq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := iaq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// IntegrationAttachmentGroupBy is the group-by builder for IntegrationAttachment entities.
type IntegrationAttachmentGroupBy struct {
	selector
	build *IntegrationAttachmentQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (iagb *IntegrationAttachmentGroupBy) Aggregate(fns ...AggregateFunc) *IntegrationAttachmentGroupBy {
	iagb.fns = append(iagb.fns, fns...)
	return iagb
}

// Scan applies the selector query and scans the result into the given value.
func (iagb *IntegrationAttachmentGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, iagb.build.ctx, "GroupBy")
	if err := iagb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*IntegrationAttachmentQuery, *IntegrationAttachmentGroupBy](ctx, iagb.build, iagb, iagb.build.inters, v)
}

func (iagb *IntegrationAttachmentGroupBy) sqlScan(ctx context.Context, root *IntegrationAttachmentQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(iagb.fns))
	for _, fn := range iagb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*iagb.flds)+len(iagb.fns))
		for _, f := range *iagb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*iagb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := iagb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// IntegrationAttachmentSelect is the builder for selecting fields of IntegrationAttachment entities.
type IntegrationAttachmentSelect struct {
	*IntegrationAttachmentQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (ias *IntegrationAttachmentSelect) Aggregate(fns ...AggregateFunc) *IntegrationAttachmentSelect {
	ias.fns = append(ias.fns, fns...)
	return ias
}

// Scan applies the selector query and scans the result into the given value.
func (ias *IntegrationAttachmentSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, ias.ctx, "Select")
	if err := ias.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*IntegrationAttachmentQuery, *IntegrationAttachmentSelect](ctx, ias.IntegrationAttachmentQuery, ias, ias.inters, v)
}

func (ias *IntegrationAttachmentSelect) sqlScan(ctx context.Context, root *IntegrationAttachmentQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(ias.fns))
	for _, fn := range ias.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*ias.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := ias.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

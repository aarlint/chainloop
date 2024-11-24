// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"database/sql/driver"
	"fmt"
	"math"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/casbackend"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/predicate"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/projectversion"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/workflow"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/workflowcontractversion"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/workflowrun"
	"github.com/google/uuid"
)

// WorkflowRunQuery is the builder for querying WorkflowRun entities.
type WorkflowRunQuery struct {
	config
	ctx                 *QueryContext
	order               []workflowrun.OrderOption
	inters              []Interceptor
	predicates          []predicate.WorkflowRun
	withWorkflow        *WorkflowQuery
	withContractVersion *WorkflowContractVersionQuery
	withCasBackends     *CASBackendQuery
	withVersion         *ProjectVersionQuery
	withFKs             bool
	modifiers           []func(*sql.Selector)
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the WorkflowRunQuery builder.
func (wrq *WorkflowRunQuery) Where(ps ...predicate.WorkflowRun) *WorkflowRunQuery {
	wrq.predicates = append(wrq.predicates, ps...)
	return wrq
}

// Limit the number of records to be returned by this query.
func (wrq *WorkflowRunQuery) Limit(limit int) *WorkflowRunQuery {
	wrq.ctx.Limit = &limit
	return wrq
}

// Offset to start from.
func (wrq *WorkflowRunQuery) Offset(offset int) *WorkflowRunQuery {
	wrq.ctx.Offset = &offset
	return wrq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (wrq *WorkflowRunQuery) Unique(unique bool) *WorkflowRunQuery {
	wrq.ctx.Unique = &unique
	return wrq
}

// Order specifies how the records should be ordered.
func (wrq *WorkflowRunQuery) Order(o ...workflowrun.OrderOption) *WorkflowRunQuery {
	wrq.order = append(wrq.order, o...)
	return wrq
}

// QueryWorkflow chains the current query on the "workflow" edge.
func (wrq *WorkflowRunQuery) QueryWorkflow() *WorkflowQuery {
	query := (&WorkflowClient{config: wrq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := wrq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := wrq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(workflowrun.Table, workflowrun.FieldID, selector),
			sqlgraph.To(workflow.Table, workflow.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, workflowrun.WorkflowTable, workflowrun.WorkflowColumn),
		)
		fromU = sqlgraph.SetNeighbors(wrq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryContractVersion chains the current query on the "contract_version" edge.
func (wrq *WorkflowRunQuery) QueryContractVersion() *WorkflowContractVersionQuery {
	query := (&WorkflowContractVersionClient{config: wrq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := wrq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := wrq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(workflowrun.Table, workflowrun.FieldID, selector),
			sqlgraph.To(workflowcontractversion.Table, workflowcontractversion.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, workflowrun.ContractVersionTable, workflowrun.ContractVersionColumn),
		)
		fromU = sqlgraph.SetNeighbors(wrq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryCasBackends chains the current query on the "cas_backends" edge.
func (wrq *WorkflowRunQuery) QueryCasBackends() *CASBackendQuery {
	query := (&CASBackendClient{config: wrq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := wrq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := wrq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(workflowrun.Table, workflowrun.FieldID, selector),
			sqlgraph.To(casbackend.Table, casbackend.FieldID),
			sqlgraph.Edge(sqlgraph.M2M, false, workflowrun.CasBackendsTable, workflowrun.CasBackendsPrimaryKey...),
		)
		fromU = sqlgraph.SetNeighbors(wrq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryVersion chains the current query on the "version" edge.
func (wrq *WorkflowRunQuery) QueryVersion() *ProjectVersionQuery {
	query := (&ProjectVersionClient{config: wrq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := wrq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := wrq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(workflowrun.Table, workflowrun.FieldID, selector),
			sqlgraph.To(projectversion.Table, projectversion.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, workflowrun.VersionTable, workflowrun.VersionColumn),
		)
		fromU = sqlgraph.SetNeighbors(wrq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first WorkflowRun entity from the query.
// Returns a *NotFoundError when no WorkflowRun was found.
func (wrq *WorkflowRunQuery) First(ctx context.Context) (*WorkflowRun, error) {
	nodes, err := wrq.Limit(1).All(setContextOp(ctx, wrq.ctx, ent.OpQueryFirst))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{workflowrun.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (wrq *WorkflowRunQuery) FirstX(ctx context.Context) *WorkflowRun {
	node, err := wrq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first WorkflowRun ID from the query.
// Returns a *NotFoundError when no WorkflowRun ID was found.
func (wrq *WorkflowRunQuery) FirstID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = wrq.Limit(1).IDs(setContextOp(ctx, wrq.ctx, ent.OpQueryFirstID)); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{workflowrun.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (wrq *WorkflowRunQuery) FirstIDX(ctx context.Context) uuid.UUID {
	id, err := wrq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single WorkflowRun entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one WorkflowRun entity is found.
// Returns a *NotFoundError when no WorkflowRun entities are found.
func (wrq *WorkflowRunQuery) Only(ctx context.Context) (*WorkflowRun, error) {
	nodes, err := wrq.Limit(2).All(setContextOp(ctx, wrq.ctx, ent.OpQueryOnly))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{workflowrun.Label}
	default:
		return nil, &NotSingularError{workflowrun.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (wrq *WorkflowRunQuery) OnlyX(ctx context.Context) *WorkflowRun {
	node, err := wrq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only WorkflowRun ID in the query.
// Returns a *NotSingularError when more than one WorkflowRun ID is found.
// Returns a *NotFoundError when no entities are found.
func (wrq *WorkflowRunQuery) OnlyID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = wrq.Limit(2).IDs(setContextOp(ctx, wrq.ctx, ent.OpQueryOnlyID)); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{workflowrun.Label}
	default:
		err = &NotSingularError{workflowrun.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (wrq *WorkflowRunQuery) OnlyIDX(ctx context.Context) uuid.UUID {
	id, err := wrq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of WorkflowRuns.
func (wrq *WorkflowRunQuery) All(ctx context.Context) ([]*WorkflowRun, error) {
	ctx = setContextOp(ctx, wrq.ctx, ent.OpQueryAll)
	if err := wrq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*WorkflowRun, *WorkflowRunQuery]()
	return withInterceptors[[]*WorkflowRun](ctx, wrq, qr, wrq.inters)
}

// AllX is like All, but panics if an error occurs.
func (wrq *WorkflowRunQuery) AllX(ctx context.Context) []*WorkflowRun {
	nodes, err := wrq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of WorkflowRun IDs.
func (wrq *WorkflowRunQuery) IDs(ctx context.Context) (ids []uuid.UUID, err error) {
	if wrq.ctx.Unique == nil && wrq.path != nil {
		wrq.Unique(true)
	}
	ctx = setContextOp(ctx, wrq.ctx, ent.OpQueryIDs)
	if err = wrq.Select(workflowrun.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (wrq *WorkflowRunQuery) IDsX(ctx context.Context) []uuid.UUID {
	ids, err := wrq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (wrq *WorkflowRunQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, wrq.ctx, ent.OpQueryCount)
	if err := wrq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, wrq, querierCount[*WorkflowRunQuery](), wrq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (wrq *WorkflowRunQuery) CountX(ctx context.Context) int {
	count, err := wrq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (wrq *WorkflowRunQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, wrq.ctx, ent.OpQueryExist)
	switch _, err := wrq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (wrq *WorkflowRunQuery) ExistX(ctx context.Context) bool {
	exist, err := wrq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the WorkflowRunQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (wrq *WorkflowRunQuery) Clone() *WorkflowRunQuery {
	if wrq == nil {
		return nil
	}
	return &WorkflowRunQuery{
		config:              wrq.config,
		ctx:                 wrq.ctx.Clone(),
		order:               append([]workflowrun.OrderOption{}, wrq.order...),
		inters:              append([]Interceptor{}, wrq.inters...),
		predicates:          append([]predicate.WorkflowRun{}, wrq.predicates...),
		withWorkflow:        wrq.withWorkflow.Clone(),
		withContractVersion: wrq.withContractVersion.Clone(),
		withCasBackends:     wrq.withCasBackends.Clone(),
		withVersion:         wrq.withVersion.Clone(),
		// clone intermediate query.
		sql:       wrq.sql.Clone(),
		path:      wrq.path,
		modifiers: append([]func(*sql.Selector){}, wrq.modifiers...),
	}
}

// WithWorkflow tells the query-builder to eager-load the nodes that are connected to
// the "workflow" edge. The optional arguments are used to configure the query builder of the edge.
func (wrq *WorkflowRunQuery) WithWorkflow(opts ...func(*WorkflowQuery)) *WorkflowRunQuery {
	query := (&WorkflowClient{config: wrq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	wrq.withWorkflow = query
	return wrq
}

// WithContractVersion tells the query-builder to eager-load the nodes that are connected to
// the "contract_version" edge. The optional arguments are used to configure the query builder of the edge.
func (wrq *WorkflowRunQuery) WithContractVersion(opts ...func(*WorkflowContractVersionQuery)) *WorkflowRunQuery {
	query := (&WorkflowContractVersionClient{config: wrq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	wrq.withContractVersion = query
	return wrq
}

// WithCasBackends tells the query-builder to eager-load the nodes that are connected to
// the "cas_backends" edge. The optional arguments are used to configure the query builder of the edge.
func (wrq *WorkflowRunQuery) WithCasBackends(opts ...func(*CASBackendQuery)) *WorkflowRunQuery {
	query := (&CASBackendClient{config: wrq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	wrq.withCasBackends = query
	return wrq
}

// WithVersion tells the query-builder to eager-load the nodes that are connected to
// the "version" edge. The optional arguments are used to configure the query builder of the edge.
func (wrq *WorkflowRunQuery) WithVersion(opts ...func(*ProjectVersionQuery)) *WorkflowRunQuery {
	query := (&ProjectVersionClient{config: wrq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	wrq.withVersion = query
	return wrq
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
//	client.WorkflowRun.Query().
//		GroupBy(workflowrun.FieldCreatedAt).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (wrq *WorkflowRunQuery) GroupBy(field string, fields ...string) *WorkflowRunGroupBy {
	wrq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &WorkflowRunGroupBy{build: wrq}
	grbuild.flds = &wrq.ctx.Fields
	grbuild.label = workflowrun.Label
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
//	client.WorkflowRun.Query().
//		Select(workflowrun.FieldCreatedAt).
//		Scan(ctx, &v)
func (wrq *WorkflowRunQuery) Select(fields ...string) *WorkflowRunSelect {
	wrq.ctx.Fields = append(wrq.ctx.Fields, fields...)
	sbuild := &WorkflowRunSelect{WorkflowRunQuery: wrq}
	sbuild.label = workflowrun.Label
	sbuild.flds, sbuild.scan = &wrq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a WorkflowRunSelect configured with the given aggregations.
func (wrq *WorkflowRunQuery) Aggregate(fns ...AggregateFunc) *WorkflowRunSelect {
	return wrq.Select().Aggregate(fns...)
}

func (wrq *WorkflowRunQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range wrq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, wrq); err != nil {
				return err
			}
		}
	}
	for _, f := range wrq.ctx.Fields {
		if !workflowrun.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if wrq.path != nil {
		prev, err := wrq.path(ctx)
		if err != nil {
			return err
		}
		wrq.sql = prev
	}
	return nil
}

func (wrq *WorkflowRunQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*WorkflowRun, error) {
	var (
		nodes       = []*WorkflowRun{}
		withFKs     = wrq.withFKs
		_spec       = wrq.querySpec()
		loadedTypes = [4]bool{
			wrq.withWorkflow != nil,
			wrq.withContractVersion != nil,
			wrq.withCasBackends != nil,
			wrq.withVersion != nil,
		}
	)
	if wrq.withContractVersion != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, workflowrun.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*WorkflowRun).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &WorkflowRun{config: wrq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	if len(wrq.modifiers) > 0 {
		_spec.Modifiers = wrq.modifiers
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, wrq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := wrq.withWorkflow; query != nil {
		if err := wrq.loadWorkflow(ctx, query, nodes, nil,
			func(n *WorkflowRun, e *Workflow) { n.Edges.Workflow = e }); err != nil {
			return nil, err
		}
	}
	if query := wrq.withContractVersion; query != nil {
		if err := wrq.loadContractVersion(ctx, query, nodes, nil,
			func(n *WorkflowRun, e *WorkflowContractVersion) { n.Edges.ContractVersion = e }); err != nil {
			return nil, err
		}
	}
	if query := wrq.withCasBackends; query != nil {
		if err := wrq.loadCasBackends(ctx, query, nodes,
			func(n *WorkflowRun) { n.Edges.CasBackends = []*CASBackend{} },
			func(n *WorkflowRun, e *CASBackend) { n.Edges.CasBackends = append(n.Edges.CasBackends, e) }); err != nil {
			return nil, err
		}
	}
	if query := wrq.withVersion; query != nil {
		if err := wrq.loadVersion(ctx, query, nodes, nil,
			func(n *WorkflowRun, e *ProjectVersion) { n.Edges.Version = e }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (wrq *WorkflowRunQuery) loadWorkflow(ctx context.Context, query *WorkflowQuery, nodes []*WorkflowRun, init func(*WorkflowRun), assign func(*WorkflowRun, *Workflow)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*WorkflowRun)
	for i := range nodes {
		fk := nodes[i].WorkflowID
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
			return fmt.Errorf(`unexpected foreign-key "workflow_id" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (wrq *WorkflowRunQuery) loadContractVersion(ctx context.Context, query *WorkflowContractVersionQuery, nodes []*WorkflowRun, init func(*WorkflowRun), assign func(*WorkflowRun, *WorkflowContractVersion)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*WorkflowRun)
	for i := range nodes {
		if nodes[i].workflow_run_contract_version == nil {
			continue
		}
		fk := *nodes[i].workflow_run_contract_version
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(workflowcontractversion.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "workflow_run_contract_version" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (wrq *WorkflowRunQuery) loadCasBackends(ctx context.Context, query *CASBackendQuery, nodes []*WorkflowRun, init func(*WorkflowRun), assign func(*WorkflowRun, *CASBackend)) error {
	edgeIDs := make([]driver.Value, len(nodes))
	byID := make(map[uuid.UUID]*WorkflowRun)
	nids := make(map[uuid.UUID]map[*WorkflowRun]struct{})
	for i, node := range nodes {
		edgeIDs[i] = node.ID
		byID[node.ID] = node
		if init != nil {
			init(node)
		}
	}
	query.Where(func(s *sql.Selector) {
		joinT := sql.Table(workflowrun.CasBackendsTable)
		s.Join(joinT).On(s.C(casbackend.FieldID), joinT.C(workflowrun.CasBackendsPrimaryKey[1]))
		s.Where(sql.InValues(joinT.C(workflowrun.CasBackendsPrimaryKey[0]), edgeIDs...))
		columns := s.SelectedColumns()
		s.Select(joinT.C(workflowrun.CasBackendsPrimaryKey[0]))
		s.AppendSelect(columns...)
		s.SetDistinct(false)
	})
	if err := query.prepareQuery(ctx); err != nil {
		return err
	}
	qr := QuerierFunc(func(ctx context.Context, q Query) (Value, error) {
		return query.sqlAll(ctx, func(_ context.Context, spec *sqlgraph.QuerySpec) {
			assign := spec.Assign
			values := spec.ScanValues
			spec.ScanValues = func(columns []string) ([]any, error) {
				values, err := values(columns[1:])
				if err != nil {
					return nil, err
				}
				return append([]any{new(uuid.UUID)}, values...), nil
			}
			spec.Assign = func(columns []string, values []any) error {
				outValue := *values[0].(*uuid.UUID)
				inValue := *values[1].(*uuid.UUID)
				if nids[inValue] == nil {
					nids[inValue] = map[*WorkflowRun]struct{}{byID[outValue]: {}}
					return assign(columns[1:], values[1:])
				}
				nids[inValue][byID[outValue]] = struct{}{}
				return nil
			}
		})
	})
	neighbors, err := withInterceptors[[]*CASBackend](ctx, query, qr, query.inters)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected "cas_backends" node returned %v`, n.ID)
		}
		for kn := range nodes {
			assign(kn, n)
		}
	}
	return nil
}
func (wrq *WorkflowRunQuery) loadVersion(ctx context.Context, query *ProjectVersionQuery, nodes []*WorkflowRun, init func(*WorkflowRun), assign func(*WorkflowRun, *ProjectVersion)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*WorkflowRun)
	for i := range nodes {
		fk := nodes[i].VersionID
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(projectversion.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "version_id" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (wrq *WorkflowRunQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := wrq.querySpec()
	if len(wrq.modifiers) > 0 {
		_spec.Modifiers = wrq.modifiers
	}
	_spec.Node.Columns = wrq.ctx.Fields
	if len(wrq.ctx.Fields) > 0 {
		_spec.Unique = wrq.ctx.Unique != nil && *wrq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, wrq.driver, _spec)
}

func (wrq *WorkflowRunQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(workflowrun.Table, workflowrun.Columns, sqlgraph.NewFieldSpec(workflowrun.FieldID, field.TypeUUID))
	_spec.From = wrq.sql
	if unique := wrq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if wrq.path != nil {
		_spec.Unique = true
	}
	if fields := wrq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, workflowrun.FieldID)
		for i := range fields {
			if fields[i] != workflowrun.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
		if wrq.withWorkflow != nil {
			_spec.Node.AddColumnOnce(workflowrun.FieldWorkflowID)
		}
		if wrq.withVersion != nil {
			_spec.Node.AddColumnOnce(workflowrun.FieldVersionID)
		}
	}
	if ps := wrq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := wrq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := wrq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := wrq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (wrq *WorkflowRunQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(wrq.driver.Dialect())
	t1 := builder.Table(workflowrun.Table)
	columns := wrq.ctx.Fields
	if len(columns) == 0 {
		columns = workflowrun.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if wrq.sql != nil {
		selector = wrq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if wrq.ctx.Unique != nil && *wrq.ctx.Unique {
		selector.Distinct()
	}
	for _, m := range wrq.modifiers {
		m(selector)
	}
	for _, p := range wrq.predicates {
		p(selector)
	}
	for _, p := range wrq.order {
		p(selector)
	}
	if offset := wrq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := wrq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// ForUpdate locks the selected rows against concurrent updates, and prevent them from being
// updated, deleted or "selected ... for update" by other sessions, until the transaction is
// either committed or rolled-back.
func (wrq *WorkflowRunQuery) ForUpdate(opts ...sql.LockOption) *WorkflowRunQuery {
	if wrq.driver.Dialect() == dialect.Postgres {
		wrq.Unique(false)
	}
	wrq.modifiers = append(wrq.modifiers, func(s *sql.Selector) {
		s.ForUpdate(opts...)
	})
	return wrq
}

// ForShare behaves similarly to ForUpdate, except that it acquires a shared mode lock
// on any rows that are read. Other sessions can read the rows, but cannot modify them
// until your transaction commits.
func (wrq *WorkflowRunQuery) ForShare(opts ...sql.LockOption) *WorkflowRunQuery {
	if wrq.driver.Dialect() == dialect.Postgres {
		wrq.Unique(false)
	}
	wrq.modifiers = append(wrq.modifiers, func(s *sql.Selector) {
		s.ForShare(opts...)
	})
	return wrq
}

// Modify adds a query modifier for attaching custom logic to queries.
func (wrq *WorkflowRunQuery) Modify(modifiers ...func(s *sql.Selector)) *WorkflowRunSelect {
	wrq.modifiers = append(wrq.modifiers, modifiers...)
	return wrq.Select()
}

// WorkflowRunGroupBy is the group-by builder for WorkflowRun entities.
type WorkflowRunGroupBy struct {
	selector
	build *WorkflowRunQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (wrgb *WorkflowRunGroupBy) Aggregate(fns ...AggregateFunc) *WorkflowRunGroupBy {
	wrgb.fns = append(wrgb.fns, fns...)
	return wrgb
}

// Scan applies the selector query and scans the result into the given value.
func (wrgb *WorkflowRunGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, wrgb.build.ctx, ent.OpQueryGroupBy)
	if err := wrgb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*WorkflowRunQuery, *WorkflowRunGroupBy](ctx, wrgb.build, wrgb, wrgb.build.inters, v)
}

func (wrgb *WorkflowRunGroupBy) sqlScan(ctx context.Context, root *WorkflowRunQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(wrgb.fns))
	for _, fn := range wrgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*wrgb.flds)+len(wrgb.fns))
		for _, f := range *wrgb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*wrgb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := wrgb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// WorkflowRunSelect is the builder for selecting fields of WorkflowRun entities.
type WorkflowRunSelect struct {
	*WorkflowRunQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (wrs *WorkflowRunSelect) Aggregate(fns ...AggregateFunc) *WorkflowRunSelect {
	wrs.fns = append(wrs.fns, fns...)
	return wrs
}

// Scan applies the selector query and scans the result into the given value.
func (wrs *WorkflowRunSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, wrs.ctx, ent.OpQuerySelect)
	if err := wrs.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*WorkflowRunQuery, *WorkflowRunSelect](ctx, wrs.WorkflowRunQuery, wrs, wrs.inters, v)
}

func (wrs *WorkflowRunSelect) sqlScan(ctx context.Context, root *WorkflowRunQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(wrs.fns))
	for _, fn := range wrs.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*wrs.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := wrs.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// Modify adds a query modifier for attaching custom logic to queries.
func (wrs *WorkflowRunSelect) Modify(modifiers ...func(s *sql.Selector)) *WorkflowRunSelect {
	wrs.modifiers = append(wrs.modifiers, modifiers...)
	return wrs
}

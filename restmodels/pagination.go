package restmodels

// Pagination describes an offset/limit window over a result set.
// A zero value (Limit == 0) means "unbounded" and is used for internal
// lookups that must not be truncated.
type Pagination struct {
	Offset int
	Limit  int
}

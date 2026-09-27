package mariadb

import (
	"testing"

	"github.com/Kaese72/huemie-lib/query"
)

// These exercise userFilters/userSortFields directly (no DB needed, since
// query.Translate/BuildOrderBy are pure functions) - they catch a typo'd
// column name or operator wiring without needing testcontainers/Docker.
func TestUserFilters(t *testing.T) {
	t.Run("username text-contains", func(t *testing.T) {
		fragments, args, err := query.Translate([]query.Filter{
			{Field: "username", Operator: "text-contains", Value: "ali"},
		}, userFilters)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(fragments) != 1 || len(args) != 1 {
			t.Fatalf("unexpected result: fragments=%v args=%v", fragments, args)
		}
	})

	t.Run("isAdmin bool-eq", func(t *testing.T) {
		fragments, args, err := query.Translate([]query.Filter{
			{Field: "isAdmin", Operator: "bool-eq", Value: "false"},
		}, userFilters)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(fragments) != 1 || len(args) != 1 || args[0] != false {
			t.Fatalf("unexpected result: fragments=%v args=%v", fragments, args)
		}
	})

	t.Run("unknown field", func(t *testing.T) {
		if _, _, err := query.Translate([]query.Filter{
			{Field: "cloudUserId", Operator: "eq", Value: "1"},
		}, userFilters); err == nil {
			t.Fatal("expected an error for an unfiltered field")
		}
	})
}

func TestUserSortFields(t *testing.T) {
	t.Run("empty falls back to username", func(t *testing.T) {
		clause, err := query.BuildOrderBy(nil, userSortFields, "username")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if clause != "username" {
			t.Fatalf("expected fallback \"username\", got %q", clause)
		}
	})

	t.Run("sort by createdAt desc", func(t *testing.T) {
		clause, err := query.BuildOrderBy([]query.Sort{{Field: "createdAt", Direction: "desc"}}, userSortFields, "username")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if clause != "createdAt DESC" {
			t.Fatalf("unexpected clause: %q", clause)
		}
	})

	t.Run("unknown field", func(t *testing.T) {
		if _, err := query.BuildOrderBy([]query.Sort{{Field: "cloudUserId", Direction: "asc"}}, userSortFields, "username"); err == nil {
			t.Fatal("expected an error for an unsortable field")
		}
	})
}

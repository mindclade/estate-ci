package auth

import (
	"context"
	"errors"
	"testing"
)

type membershipFixture map[string]map[string]bool

func (fixture membershipFixture) HasTransitiveMembership(_ context.Context, group, email string) (bool, error) {
	if email == "error@mindclade.example" {
		return false, errors.New("directory unavailable")
	}
	return fixture[group][email], nil
}

func TestWorkspaceGroupRolesAreTransitiveAndFailClosed(t *testing.T) {
	resolver, err := NewWorkspaceRoleResolver([]GroupBinding{
		{Resource: "groups/viewers", Role: "viewer"},
		{Resource: "groups/operators", Role: "operator"},
		{Resource: "groups/admins", Role: "admin"},
	}, membershipFixture{
		"groups/viewers":   {"viewer@mindclade.example": true},
		"groups/operators": {"operator@mindclade.example": true},
		"groups/admins":    {"admin@mindclade.example": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	for email, expected := range map[string]Role{
		"viewer@mindclade.example":   RoleViewer,
		"operator@mindclade.example": RoleOperator,
		"admin@mindclade.example":    RoleAdmin,
		"outsider@mindclade.example": RoleNone,
	} {
		role, err := resolver.RoleFor(context.Background(), email)
		if err != nil || role != expected {
			t.Fatalf("RoleFor(%s) = %s, %v; want %s", email, role, err, expected)
		}
	}
	if role, err := resolver.RoleFor(context.Background(), "error@mindclade.example"); err == nil || role != RoleNone {
		t.Fatal("directory error did not fail closed")
	}
	if role, err := resolver.RoleFor(context.Background(), "o'hare@mindclade.example"); err == nil || role != RoleNone {
		t.Fatal("filter control character in identity did not fail closed")
	}
}

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type Role int

var workspaceEmailPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._+%-]{0,127}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

const (
	RoleNone Role = iota
	RoleViewer
	RoleOperator
	RoleApprover
	RoleAdmin
)

func (role Role) String() string {
	switch role {
	case RoleViewer:
		return "viewer"
	case RoleOperator:
		return "operator"
	case RoleApprover:
		return "approver"
	case RoleAdmin:
		return "admin"
	default:
		return "none"
	}
}

func ParseRole(value string) (Role, error) {
	switch value {
	case "viewer":
		return RoleViewer, nil
	case "operator":
		return RoleOperator, nil
	case "approver":
		return RoleApprover, nil
	case "admin":
		return RoleAdmin, nil
	default:
		return RoleNone, fmt.Errorf("unknown role %q", value)
	}
}

type GroupBinding struct {
	Resource string `json:"resource"`
	Role     string `json:"role"`
}

type MembershipChecker interface {
	HasTransitiveMembership(context.Context, string, string) (bool, error)
}

type RoleResolver interface {
	RoleFor(context.Context, string) (Role, error)
}

type WorkspaceRoleResolver struct {
	bindings []resolvedBinding
	checker  MembershipChecker
	now      func() time.Time
	ttl      time.Duration
	mu       sync.Mutex
	cache    map[string]cachedRole
}

type resolvedBinding struct {
	resource string
	role     Role
}

type cachedRole struct {
	role    Role
	expires time.Time
}

func NewWorkspaceRoleResolver(bindings []GroupBinding, checker MembershipChecker) (*WorkspaceRoleResolver, error) {
	if checker == nil || len(bindings) == 0 || len(bindings) > 20 {
		return nil, errors.New("Workspace group role configuration is required")
	}
	resourcePattern := regexp.MustCompile(`^groups/[A-Za-z0-9_-]{1,128}$`)
	seen := map[string]bool{}
	resolved := make([]resolvedBinding, 0, len(bindings))
	for _, binding := range bindings {
		role, err := ParseRole(binding.Role)
		if err != nil || !resourcePattern.MatchString(binding.Resource) || seen[binding.Resource] {
			return nil, errors.New("Workspace group role binding is invalid")
		}
		seen[binding.Resource] = true
		resolved = append(resolved, resolvedBinding{resource: binding.Resource, role: role})
	}
	sort.Slice(resolved, func(i, j int) bool { return resolved[i].role > resolved[j].role })
	return &WorkspaceRoleResolver{bindings: resolved, checker: checker, now: time.Now, ttl: 2 * time.Minute, cache: map[string]cachedRole{}}, nil
}

func (resolver *WorkspaceRoleResolver) RoleFor(ctx context.Context, email string) (Role, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if len(email) > 320 || !workspaceEmailPattern.MatchString(email) {
		return RoleNone, errors.New("membership identity is invalid")
	}
	resolver.mu.Lock()
	if cached, ok := resolver.cache[email]; ok && resolver.now().Before(cached.expires) {
		resolver.mu.Unlock()
		return cached.role, nil
	}
	resolver.mu.Unlock()
	role := RoleNone
	for _, binding := range resolver.bindings {
		member, err := resolver.checker.HasTransitiveMembership(ctx, binding.resource, email)
		if err != nil {
			return RoleNone, fmt.Errorf("resolve Workspace role: %w", err)
		}
		if member {
			role = binding.role
			break
		}
	}
	resolver.mu.Lock()
	if len(resolver.cache) >= 10000 {
		resolver.cache = map[string]cachedRole{}
	}
	resolver.cache[email] = cachedRole{role: role, expires: resolver.now().Add(resolver.ttl)}
	resolver.mu.Unlock()
	return role, nil
}

type CloudIdentityChecker struct {
	client  *http.Client
	baseURL string
}

func NewCloudIdentityChecker(client *http.Client) (*CloudIdentityChecker, error) {
	if client == nil {
		return nil, errors.New("Cloud Identity ADC client is required")
	}
	client.Timeout = 10 * time.Second
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errors.New("Cloud Identity redirects are forbidden")
	}
	return &CloudIdentityChecker{client: client, baseURL: "https://cloudidentity.googleapis.com"}, nil
}

func (checker *CloudIdentityChecker) HasTransitiveMembership(ctx context.Context, group, email string) (bool, error) {
	if !workspaceEmailPattern.MatchString(email) {
		return false, errors.New("Cloud Identity membership email is invalid")
	}
	query := "member_key_id == '" + email + "'"
	endpoint := checker.baseURL + "/v1/" + group + "/memberships:checkTransitiveMembership?query=" + url.QueryEscape(query)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	response, err := checker.client.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false, fmt.Errorf("Cloud Identity returned HTTP %d", response.StatusCode)
	}
	var payload struct {
		HasMembership bool `json:"hasMembership"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 32*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return false, errors.New("Cloud Identity response is invalid")
	}
	return payload.HasMembership, nil
}

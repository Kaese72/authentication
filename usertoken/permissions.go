package usertoken

import "encoding/json"

// ClaimPermissions is the name of the claim ("hp", for "humi permissions")
// holding the authenticated user's permissions.
const ClaimPermissions = "hp"

// claimAdminKey is the key within the hp claim that, when true, grants every
// permission unconditionally and makes every other key in the claim
// irrelevant.
const claimAdminKey = "admin"

// accessAll is the only value View and Modify can hold today. It exists as a
// named constant, rather than every caller writing "*", so the future
// addition of a value that names specific items (a list of device IDs,
// say) instead of granting everything is a change to what this constant is
// compared against, not to every call site.
const accessAll = "*"

// Well-known resource codes. Centralized here so every service that embeds
// or checks permissions agrees on what a code means and no two pick the same
// short code for different things. What exactly a resource covers is up to
// each consuming service to decide - these are deliberately coarse-grained
// for now (e.g. ResourceDevices covers all devices, not one).
const (
	ResourceDevices         = "ds" // device-store: devices and their capabilities
	ResourceAutomationRules = "ar" // ittt-orchestrator: automation rules
	ResourceUsers           = "us" // authentication: user accounts and their permissions
	ResourceCloudConnect    = "cc" // cloud-connect: cloud connectivity
)

// ResourceDefinition describes one resource code for display purposes: its
// code (as used in the hp claim and in HasView/HasModify checks) and a
// human-readable name. A UI fetches Resources (via the authentication
// service's /permissions/resources endpoint) to build a permissions editor,
// rather than hardcoding the set of resources and their names itself.
type ResourceDefinition struct {
	Code string
	Name string
}

// Resources lists every resource currently defined, in a stable display
// order, together with a human-readable name for each. Add to this list
// (and to the Resource* constants and the userPermissions.resource enum in
// authentication's migrations) when a new resource is introduced.
var Resources = []ResourceDefinition{
	{Code: ResourceDevices, Name: "Devices"},
	{Code: ResourceAutomationRules, Name: "Automation Rules"},
	{Code: ResourceUsers, Name: "Users"},
	{Code: ResourceCloudConnect, Name: "Cloud Connect"},
}

// KnownResources lists every resource code currently defined, in the same
// order as Resources, for callers (e.g. building a fixed set of rows in a
// permissions editor) that only need the codes, not the display names.
var KnownResources = func() []string {
	codes := make([]string, len(Resources))
	for i, r := range Resources {
		codes[i] = r.Code
	}
	return codes
}()

// ResourceGrant is what a user may do with one resource: View and Modify are
// each either accessAll ("*", full access) or "" (no access). This mirrors
// the shape of the hp claim rather than collapsing to a single ordinal level,
// in anticipation of a future grant that names specific items instead of
// everything. Modify implies View: a grant with only Modify set still
// behaves as full view+modify access, since there is no supported way to
// modify something one cannot see.
type ResourceGrant struct {
	View   string
	Modify string
}

// rawResourceGrant is the JSON shape of one resource's entry in the hp claim:
// {"v": "*", "m": "*"}, with either key omitted when not granted.
type rawResourceGrant struct {
	View   string `json:"v,omitempty"`
	Modify string `json:"m,omitempty"`
}

// Permissions is the parsed hp claim of a use token: either the admin flag,
// which grants everything, or a set of per-resource grants.
type Permissions struct {
	admin     bool
	resources map[string]ResourceGrant
}

// AdminPermissions returns a Permissions value with the admin flag set. Use
// it to issue tokens for administrators, and in tests and internal/system
// code paths that must bypass all permission checks.
func AdminPermissions() Permissions {
	return Permissions{admin: true}
}

// NewPermissions builds a non-admin Permissions value from a set of
// per-resource grants, keyed by resource code (see the Resource* constants).
// A resource absent from grants, or with both View and Modify empty, means
// no access to that resource.
func NewPermissions(grants map[string]ResourceGrant) Permissions {
	resources := make(map[string]ResourceGrant, len(grants))
	for resource, grant := range grants {
		if grant.View == accessAll || grant.Modify == accessAll {
			resources[resource] = grant
		}
	}
	return Permissions{resources: resources}
}

// Admin reports whether the caller has the admin flag, which grants every
// permission unconditionally. Prefer HasView / HasModify for an actual
// permission decision - they already account for this - and reserve Admin
// for code that specifically needs to know the bypass applied, e.g. to log
// it.
func (p Permissions) Admin() bool {
	return p.admin
}

// HasView reports whether the caller may view resource. Modify access
// implies view access.
func (p Permissions) HasView(resource string) bool {
	if p.admin {
		return true
	}
	grant := p.resources[resource]
	return grant.View == accessAll || grant.Modify == accessAll
}

// HasModify reports whether the caller may modify resource.
func (p Permissions) HasModify(resource string) bool {
	if p.admin {
		return true
	}
	return p.resources[resource].Modify == accessAll
}

// Grant returns the raw grant for resource, for callers (e.g. an admin UI)
// that need to display or re-issue it rather than just check it. It does not
// account for the admin flag - use Admin for that.
func (p Permissions) Grant(resource string) ResourceGrant {
	return p.resources[resource]
}

// Resources returns a copy of the caller's per-resource grants, keyed by
// resource code. Always empty when Admin is true - use Admin to check that
// case. Intended for code (e.g. persistence) that needs to enumerate exactly
// what was granted, not for permission decisions - use HasView / HasModify
// for those.
func (p Permissions) Resources() map[string]ResourceGrant {
	out := make(map[string]ResourceGrant, len(p.resources))
	for resource, grant := range p.resources {
		out[resource] = grant
	}
	return out
}

// toRaw renders p in the wire/storage shape used by both the JWT claim and
// the persisted column: {"admin": true} or {"<code>": {"v": "*", "m": "*"}, ...}.
func (p Permissions) toRaw() map[string]any {
	raw := map[string]any{}
	if p.admin {
		raw[claimAdminKey] = true
		return raw
	}
	for resource, grant := range p.resources {
		entry := rawResourceGrant{}
		if grant.View == accessAll {
			entry.View = accessAll
		}
		if grant.Modify == accessAll {
			entry.Modify = accessAll
		}
		if entry.View == "" && entry.Modify == "" {
			continue
		}
		raw[resource] = entry
	}
	return raw
}

// permissionsFromRaw parses the wire/storage shape back into a Permissions
// value. Unrecognized shapes are ignored field-by-field rather than
// rejected, so a future, richer grant value (e.g. a list of IDs instead of
// "*") degrades to "no access" for this version instead of failing to parse
// the whole claim.
func permissionsFromRaw(raw map[string]any) Permissions {
	if admin, ok := raw[claimAdminKey].(bool); ok && admin {
		return Permissions{admin: true}
	}
	resources := map[string]ResourceGrant{}
	for resource, v := range raw {
		if resource == claimAdminKey {
			continue
		}
		entryMap, ok := v.(map[string]any)
		if !ok {
			continue
		}
		var grant ResourceGrant
		if view, _ := entryMap["v"].(string); view == accessAll {
			grant.View = accessAll
		}
		if modify, _ := entryMap["m"].(string); modify == accessAll {
			grant.Modify = accessAll
		}
		if grant.View != "" || grant.Modify != "" {
			resources[resource] = grant
		}
	}
	return Permissions{resources: resources}
}

// MarshalJSON and UnmarshalJSON let Permissions be stored directly as a JSON
// column (e.g. the authentication service's persisted permissions), using
// the same shape as the hp claim.
func (p Permissions) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.toRaw())
}

func (p *Permissions) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if len(data) > 0 {
		if err := json.Unmarshal(data, &raw); err != nil {
			return err
		}
	}
	*p = permissionsFromRaw(raw)
	return nil
}

package modules

// Registry holds the enabled modules, in registration order.
type Registry struct {
	modules map[string]Module
	order   []string
}

func NewRegistry() *Registry {
	return &Registry{modules: make(map[string]Module)}
}

func (r *Registry) Register(m Module) {
	if _, exists := r.modules[m.Name()]; !exists {
		r.order = append(r.order, m.Name())
	}
	r.modules[m.Name()] = m
}

func (r *Registry) Get(name string) (Module, bool) {
	m, ok := r.modules[name]
	return m, ok
}

// Names returns registered module names in registration order, so
// listings and health output are stable rather than map-random.
func (r *Registry) Names() []string {
	return append([]string(nil), r.order...)
}

// Tools is every distinct tool the registered modules need — what the
// setup script installs and what /health reports on. Deduplicated by
// tool name, keeping the first configured path seen.
func (r *Registry) Tools() []ToolRequirement {
	seen := make(map[string]struct{})
	var out []ToolRequirement
	for _, name := range r.order {
		for _, req := range r.modules[name].RequiredTools() {
			if _, dup := seen[req.Name]; dup {
				continue
			}
			seen[req.Name] = struct{}{}
			out = append(out, req)
		}
	}
	return out
}

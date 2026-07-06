package checks

// All returns every registered check in catalog order. This order is
// the display order for the TUI/Plain renderers and must follow the
// catalog section order: LOCAL → CLUSTER → TASK → TDEF → IAM → NET.
func All() []Check {
	return []Check{
		NewLocal001(),
		NewLocal002(),
		NewCluster001(),
		NewCluster002(),
		NewCluster003(),
		NewCluster004(),
		NewCluster005(),
		NewTask001(),
		NewTask002(),
		NewTask003(),
		NewTask004(),
		NewTask005(),
		NewTdef001(),
		NewTdef002(),
		NewTdef003(),
		NewTdef004(),
		NewTdef005(),
		NewTdef006(),
		NewIam001(),
		NewIam002(),
		NewIam003(),
		NewIam004(),
		NewIam005(),
		NewIam006(),
		NewIam007(),
		NewNet001(),
		NewNet002(),
		NewNet003(),
	}
}

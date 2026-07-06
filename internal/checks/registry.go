package checks

// All returns every registered check in catalog order. This order is
// the display order for the TUI/Plain renderers and must follow the
// catalog section order: LOCAL → CLUSTER → TASK → TDEF → IAM → NET.
func All() []Check {
	return []Check{
		NewLocal001(),
		NewLocal002(),
		// TODO: CLUSTER-001..005
		NewTask001(),
		NewTask002(),
		NewTask003(),
		// TODO: TASK-004, TASK-005
		NewTdef001(),
		// TODO: TDEF-002..006, IAM-001..007, NET-001..003
	}
}

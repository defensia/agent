package collector

// CollectKeySoftwareForDiag exposes the inventory for out-of-band verification.
//
// The inventory is assembled from several sources whose interaction is the
// interesting part — host rows, node rows read through PID 1, container rows read
// through each container's own root — and until now the only way to see the
// result was to register an agent against production. This lets it be read on a
// machine without touching the panel.
func CollectKeySoftwareForDiag() []KeySoftware {
	return collectKeySoftware()
}

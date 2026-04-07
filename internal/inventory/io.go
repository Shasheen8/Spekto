package inventory

import (
	"encoding/json"
	"fmt"
	"os"
)

func ParseInventory(data []byte) (Inventory, error) {
	var inv Inventory
	if err := json.Unmarshal(data, &inv); err != nil {
		return Inventory{}, err
	}
	if inv.Operations == nil {
		inv.Operations = []Operation{}
	}
	for i := range inv.Operations {
		inv.Operations[i] = applyDerivedSignals(inv.Operations[i])
	}
	inv.Summary = summarize(inv.Operations)
	return inv, nil
}

func LoadInventoryFile(path string) (Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Inventory{}, fmt.Errorf("read inventory: %w", err)
	}
	return ParseInventory(data)
}

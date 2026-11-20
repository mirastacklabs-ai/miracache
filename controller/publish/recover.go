package publish

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"

	"github.com/BurntSushi/toml"

	"miracache/controller/bundle"
	"miracache/controller/store"
)

// Recover rebuilds the store's state from a memory node's bundle.current (`--recover-from`):
// membership (desired nodes by admin address), sec (principals, rbac), config, the
// generations and the last envelope. The envelope must verify against trust. It refuses a node
// that is behind the store. The signing keys are not recoverable and must come from backup.
func Recover(ctx context.Context, c *NodeClient, trust *bundle.TrustKeys, st *store.Store, admin string, log *slog.Logger) error {
	raw, err := c.GetBundle(ctx, admin)
	if err != nil {
		return fmt.Errorf("recover-from %s: %w", admin, err)
	}
	b, err := bundle.Open(trust, raw)
	if err != nil {
		return fmt.Errorf("recover-from %s: the node's bundle does not verify: %w", admin, err)
	}
	cur, err := st.Load()
	if err != nil {
		return err
	}
	if cur.Generation > b.Body.Generation || cur.SecGeneration > b.Sec.SecGeneration {
		return fmt.Errorf("recover-from %s: node is at generation %d / sec_generation %d, behind the store (%d / %d); pick the node with the highest sec_generation",
			admin, b.Body.Generation, b.Sec.SecGeneration, cur.Generation, cur.SecGeneration)
	}
	next := store.State{
		Generation:    b.Body.Generation,
		SecGeneration: b.Sec.SecGeneration,
		Principals:    b.Sec.Principals,
		RBAC:          b.Sec.RBAC,
		History:       [][]byte{b.Envelope.Body},
		LastEnvelope:  raw,
	}
	for _, n := range b.Body.Membership.Nodes {
		next.Nodes = append(next.Nodes, store.DesiredNode{Admin: n.Admin, Weight: n.Weight, Zone: n.Zone, State: n.State})
	}
	if len(b.Body.Config) > 0 {
		var buf bytes.Buffer
		if err := toml.NewEncoder(&buf).Encode(map[string]any{"config": b.Body.Config}); err != nil {
			return fmt.Errorf("recover-from %s: config: %w", admin, err)
		}
		next.ConfigTOML = buf.String()
	}
	if err := st.Commit(cur.Generation, next); err != nil {
		return err
	}
	if log != nil {
		log.Info("recovered the store from a node's bundle.current", "admin", admin,
			"generation", next.Generation, "sec_generation", next.SecGeneration, "nodes", len(next.Nodes))
	}
	return nil
}

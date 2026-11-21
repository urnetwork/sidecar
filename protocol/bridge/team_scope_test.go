package bridge

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// QD-059's wire numbers are shared by config writers, projection readers, DNS and cert delivery.
func TestTeamScopeProjectionWire(t *testing.T) {
	id := bytes.Repeat([]byte{7}, 16)
	for _, ownerField := range []protowire.Number{2, 3} {
		row := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), "one")
		row = protowire.AppendBytes(protowire.AppendTag(row, ownerField, protowire.BytesType), id)
		wire := protowire.AppendBytes(protowire.AppendTag(nil, 6, protowire.BytesType), row)
		var rows ProjectionRows
		if err := proto.Unmarshal(wire, &rows); err != nil || len(rows.TeamScopes) != 1 {
			t.Fatalf("field 6: %v, %v", rows.GetTeamScopes(), err)
		}
		scope := rows.TeamScopes[0]
		if scope.Label != "one" || (ownerField == 2 && !bytes.Equal(scope.GetMemberId(), id)) ||
			(ownerField == 3 && !bytes.Equal(scope.GetTagAtom(), id)) {
			t.Fatalf("owner field %d: %v", ownerField, scope)
		}
		again, err := proto.MarshalOptions{Deterministic: true}.Marshal(&rows)
		if err != nil || !bytes.Equal(again, wire) {
			t.Fatalf("owner field %d changed in transit: %x, %v", ownerField, again, err)
		}
	}
}

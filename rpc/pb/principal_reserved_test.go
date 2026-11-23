/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package pb

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// AuthenticatedPrincipal reserves the JSON names of the meanings it carries in
// no field, so no field can take one and be read with that meaning.
func TestAuthenticatedPrincipalReservesTheNamesItCarriesNoFieldUnder(t *testing.T) {
	d := (&AuthenticatedPrincipal{}).ProtoReflect().Descriptor()
	for _, name := range []string{"platformTenantId", "customerOrgId", "userId", "partition"} {
		if !d.ReservedNames().Has(protoreflect.Name(name)) {
			t.Errorf("AuthenticatedPrincipal does not reserve %q", name)
		}
		if d.Fields().ByJSONName(name) != nil {
			t.Errorf("a field of AuthenticatedPrincipal has the JSON name %q", name)
		}
	}
}

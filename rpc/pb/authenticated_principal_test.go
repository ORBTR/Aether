/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package pb

import (
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestAuthenticatedPrincipalRoundTripIsSeparateFromMutableContext(t *testing.T) {
	request := &RPCRequest{
		Id: "principal-round-trip",
		Context: map[string]string{
			"orgId": "org-B",
		},
		Principal: &AuthenticatedPrincipal{
			Subject: "user-A",
			Axes: []*ScopeAxis{
				{Name: "platform_tenant", Value: "orbtr"},
				{Name: "customer_org", Value: "org-A"},
			},
			Scopes:      []string{"org.read", "org.write"},
			PartitionId: "org-A",
		},
	}

	wire, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var decoded RPCRequest
	if err := proto.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}

	if !proto.Equal(request.Principal, decoded.Principal) {
		t.Fatalf("principal changed in transit: got %#v want %#v", decoded.Principal, request.Principal)
	}
	if got := decoded.Principal.GetPartitionId(); got != "org-A" {
		t.Fatalf("partition = %q after the round trip, want org-A", got)
	}
	if got := decoded.Context["orgId"]; got != "org-B" {
		t.Fatalf("mutable context candidate = %q", got)
	}

	decoded.Context["orgId"] = "org-C"
	if !reflect.DeepEqual(decoded.Principal.Scopes, []string{"org.read", "org.write"}) ||
		decoded.Principal.GetAxes()[1].GetValue() != "org-A" {
		t.Fatalf("mutable context rewrote principal: %#v", decoded.Principal)
	}
}

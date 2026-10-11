package services

import (
	"regexp"
	"sort"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// The gRPC half of "API timestamps are UTC" (docs/API_REFERENCE.md,
// "Timestamps"), structural part. A google.protobuf.Timestamp is seconds+nanos
// since the Unix epoch: it has no zone, so every Timestamp field is UTC by
// construction. A time sent as a STRING is only as UTC as the code formatting
// it, so every string field in any RPC response message whose name says it holds
// a time must be listed in reviewedProtoStringTimeFields, naming how it is
// produced. A new string time field fails here until someone checks it.
//
// The name match (protoStringTimeName) is the limit of this check: a string
// field named "issued" holding a time is invisible to it. The runtime sweep
// (server/faultops TestUTCResponseGuard) scans every string VALUE of every read
// RPC it can call for a non-UTC RFC 3339 time, whatever the field is called.
var reviewedProtoStringTimeFields = map[string]string{
	"keyorix.v1.SecretACLEntry.created_at": "secret_service.go formats a.CreatedAt.UTC() as 2006-01-02T15:04:05Z",
	"keyorix.v1.SystemInfo.build_time":     "never set by system_service.go GetSystemInfo (always empty); set it as UTC if it is ever filled",
	"keyorix.v1.SystemInfo.uptime":         "never set by GetSystemInfo (always empty); a duration, not a point in time, if filled",
}

var protoStringTimeName = regexp.MustCompile(`(?i)(_at|_on|time|date|timestamp|since|until|expir\w*|deadline|uptime)$`)

func TestUTCStructural_ProtoStringTimeFieldsAreReviewed(t *testing.T) {
	file := pb.File_keyorix_proto
	seen := map[protoreflect.FullName]bool{}
	found := map[string]bool{}
	timestamps := 0

	var walk func(md protoreflect.MessageDescriptor)
	walk = func(md protoreflect.MessageDescriptor) {
		if seen[md.FullName()] {
			return
		}
		seen[md.FullName()] = true
		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			f := fields.Get(i)
			kind, msg := f.Kind(), f.Message()
			if f.IsMap() {
				kind, msg = f.MapValue().Kind(), f.MapValue().Message()
			}
			switch kind {
			case protoreflect.StringKind:
				if protoStringTimeName.MatchString(string(f.Name())) {
					found[string(f.FullName())] = true
				}
			case protoreflect.MessageKind, protoreflect.GroupKind:
				if msg.FullName() == "google.protobuf.Timestamp" {
					timestamps++
					continue
				}
				walk(msg)
			}
		}
	}
	services := file.Services()
	rpcs := 0
	for i := 0; i < services.Len(); i++ {
		methods := services.Get(i).Methods()
		for j := 0; j < methods.Len(); j++ {
			rpcs++
			walk(methods.Get(j).Output())
		}
	}
	if rpcs < 50 || timestamps < 20 {
		t.Fatalf("walked %d RPCs and %d Timestamp fields: the descriptor walk is not reaching the API", rpcs, timestamps)
	}

	var errs []string
	for name := range found {
		if _, ok := reviewedProtoStringTimeFields[name]; !ok {
			errs = append(errs, name+" is a string field named like a time in an RPC response: send it as google.protobuf.Timestamp, or format it in UTC and add it to reviewedProtoStringTimeFields with how")
		}
	}
	for name := range reviewedProtoStringTimeFields {
		if !found[name] {
			errs = append(errs, "reviewedProtoStringTimeFields has "+name+", which no RPC response carries any more: remove it")
		}
	}
	sort.Strings(errs)
	for _, e := range errs {
		t.Error(e)
	}
	t.Logf("%d RPCs, %d response message types, %d Timestamp fields, %d string time fields", rpcs, len(seen), timestamps, len(found))
}

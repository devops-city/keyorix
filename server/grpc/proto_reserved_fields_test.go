package grpc_test

// proto_reserved_fields_test.go — INV-GRPC-05 (#2521).
//
// Invariant: CreateSecretRequest's field numbers 11–20 (ADR-105 §2,
// server/proto/keyorix.proto) are held for the phase-1 HTTP-parity governance
// fields and are never spent on anything else. Protobuf field numbers cannot
// be reused once a client has seen them, so a number spent on the wrong field
// is a permanent wire-contract defect.
//
// Why a test and not only `buf breaking`: buf.yaml configures `breaking: FILE`,
// but no CI workflow runs `buf breaking` (nor `buf` at all — only the
// Makefile's local `buf lint`), and wiring it in is a .github change. Even when
// run, buf breaking compares against a previous commit, so it judges any
// shrink of the reserved range the same way — it cannot tell the legitimate
// un-reserve-for-the-earmarked-field the proto comment anticipates from
// spending a held number on an unrelated field. This test encodes that intent
// instead: each number in 11–20 is either still reserved, or used by the one
// field it is earmarked for.
//
// Two independent views are checked so neither can drift alone: the compiled
// descriptor embedded in the generated pb package (what actually goes on the
// wire), and the keyorix.proto source (what the next `make proto` will
// generate).
//
// What this does NOT cover: any other message's reserved ranges, and type
// changes of an already-assigned field (buf breaking's job, still unwired).

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

const (
	heldFieldLo = 11
	heldFieldHi = 20
)

// earmarkedCreateSecretFields names the only field each held number may be
// un-reserved for (keyorix.proto's comment above `reserved 11 to 20`). 13–20
// are held for "the remaining phase-1 governance fields" without names yet:
// spending one requires naming it here, in review, first.
var earmarkedCreateSecretFields = map[protoreflect.FieldNumber]protoreflect.Name{
	11: "description",
	12: "classification",
}

// heldFieldViolations reports every way md breaks the hold on 11–20.
func heldFieldViolations(md protoreflect.MessageDescriptor) []string {
	var out []string
	reserved := md.ReservedRanges()
	for n := protoreflect.FieldNumber(heldFieldLo); n <= heldFieldHi; n++ {
		isReserved := reserved.Has(n)
		f := md.Fields().ByNumber(n)
		switch {
		case isReserved && f != nil:
			out = append(out, fmt.Sprintf("field number %d is both reserved and used by %q", n, f.Name()))
		case !isReserved && f == nil:
			out = append(out, fmt.Sprintf("field number %d is neither reserved nor used: the hold on 11–20 was dropped, so it is free to be spent on an unrelated field", n))
		case f != nil:
			if want, ok := earmarkedCreateSecretFields[n]; !ok || f.Name() != want {
				out = append(out, fmt.Sprintf("field number %d is used by %q, but it is held for %q (empty = not yet named) — field numbers can never be reused once spent", n, f.Name(), want))
			}
		}
	}
	return out
}

func TestCreateSecretRequest_HeldFieldNumbers_CompiledDescriptor(t *testing.T) {
	md := (&pb.CreateSecretRequest{}).ProtoReflect().Descriptor()
	require.Equal(t, protoreflect.FullName("keyorix.v1.CreateSecretRequest"), md.FullName())
	for _, v := range heldFieldViolations(md) {
		t.Error("CreateSecretRequest: " + v)
	}
}

// TestHeldFieldViolations_Calibration proves heldFieldViolations both ways
// against synthetic descriptors: green on the earmarked un-reserve, red on an
// unrelated field spending a held number and on a silently dropped hold.
// (The compiled pb descriptor cannot be mutated without regenerating, so the
// checker's red path is demonstrated here, permanently.)
func TestHeldFieldViolations_Calibration(t *testing.T) {
	build := func(t *testing.T, fields map[int32]string, reserved [][2]int32) protoreflect.MessageDescriptor {
		t.Helper()
		msg := &descriptorpb.DescriptorProto{Name: proto.String("CreateSecretRequest")}
		for num, name := range fields {
			msg.Field = append(msg.Field, &descriptorpb.FieldDescriptorProto{
				Name: proto.String(name), Number: proto.Int32(num),
				Type:  descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
				Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
			})
		}
		for _, r := range reserved {
			// DescriptorProto reserved ranges are end-exclusive.
			msg.ReservedRange = append(msg.ReservedRange, &descriptorpb.DescriptorProto_ReservedRange{Start: proto.Int32(r[0]), End: proto.Int32(r[1] + 1)})
		}
		fd, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
			Name: proto.String("calibration.proto"), Package: proto.String("calibration"),
			Syntax: proto.String("proto3"), MessageType: []*descriptorpb.DescriptorProto{msg},
		}, nil)
		require.NoError(t, err)
		return fd.Messages().Get(0)
	}

	assert.Empty(t, heldFieldViolations(build(t, map[int32]string{1: "name"}, [][2]int32{{11, 20}})),
		"today's shape (all of 11–20 reserved) must pass")
	assert.Empty(t, heldFieldViolations(build(t, map[int32]string{1: "name", 11: "description", 12: "classification"}, [][2]int32{{13, 20}})),
		"un-reserving 11/12 for their earmarked fields must pass")
	assert.Len(t, heldFieldViolations(build(t, map[int32]string{1: "name", 13: "owner"}, [][2]int32{{11, 12}, {14, 20}})), 1,
		"an unrelated field spending held number 13 must fail")
	assert.Len(t, heldFieldViolations(build(t, map[int32]string{1: "name", 11: "classification"}, [][2]int32{{12, 20}})), 1,
		"an earmarked field on the wrong number must fail")
	assert.Len(t, heldFieldViolations(build(t, map[int32]string{1: "name"}, nil)), heldFieldHi-heldFieldLo+1,
		"dropping the reserved statement must fail for every held number")
}

var (
	createSecretMsgRe = regexp.MustCompile(`(?s)message CreateSecretRequest \{(.*?)\n\}`)
	reservedRangeRe   = regexp.MustCompile(`(?m)^\s*reserved\s+([^;]+);`)
	fieldDeclRe       = regexp.MustCompile(`(?m)^\s*(?:optional\s+|repeated\s+)?[\w.<>, ]+\s+(\w+)\s*=\s*(\d+)\s*;`)
)

func TestCreateSecretRequest_HeldFieldNumbers_ProtoSource(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "proto", "keyorix.proto"))
	require.NoError(t, err)

	m := createSecretMsgRe.FindSubmatch(src)
	require.NotNil(t, m, "message CreateSecretRequest not found in keyorix.proto")
	body := stripProtoComments(string(m[1]))

	reserved := map[int]bool{}
	for _, r := range reservedRangeRe.FindAllStringSubmatch(body, -1) {
		for part := range strings.SplitSeq(r[1], ",") {
			part = strings.TrimSpace(part)
			if lo, hi, ok := strings.Cut(part, " to "); ok {
				l, err1 := strconv.Atoi(strings.TrimSpace(lo))
				h, err2 := strconv.Atoi(strings.TrimSpace(hi))
				require.NoErrorf(t, err1, "unparsed reserved range %q", part)
				require.NoErrorf(t, err2, "unparsed reserved range %q", part)
				for n := l; n <= h; n++ {
					reserved[n] = true
				}
			} else if n, err := strconv.Atoi(part); err == nil {
				reserved[n] = true
			} // reserved names ("foo") are not numbers; ignore
		}
	}
	used := map[int]string{}
	for _, f := range fieldDeclRe.FindAllStringSubmatch(body, -1) {
		n, _ := strconv.Atoi(f[2])
		used[n] = f[1]
	}
	require.NotEmpty(t, used, "parsed zero field declarations from CreateSecretRequest — the parser broke")

	for n := heldFieldLo; n <= heldFieldHi; n++ {
		name, isUsed := used[n]
		switch {
		case reserved[n] && isUsed:
			t.Errorf("keyorix.proto: field number %d is both reserved and used by %q", n, name)
		case !reserved[n] && !isUsed:
			t.Errorf("keyorix.proto: CreateSecretRequest field number %d is neither reserved nor used — the hold on 11–20 was dropped", n)
		case isUsed:
			want, ok := earmarkedCreateSecretFields[protoreflect.FieldNumber(n)]
			assert.Truef(t, ok && name == string(want),
				"keyorix.proto: CreateSecretRequest field number %d is used by %q, but it is held for %q (empty = not yet named)", n, name, want)
		}
	}
}

func stripProtoComments(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if before, _, ok := strings.Cut(l, "//"); ok {
			lines[i] = before
		}
	}
	return strings.Join(lines, "\n")
}

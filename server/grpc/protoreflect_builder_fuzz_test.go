package grpc_test

// protoreflect_builder_fuzz_test.go holds the generic, schema-driven machinery
// FuzzGRPCProtoreflectInvariants (protoreflect_fuzz_test.go) uses to turn raw
// fuzz bytes into a well-typed request for ANY registered keyorix.v1 RPC: method
// discovery via the live *grpc.Server's own service registry (so a newly
// registered service/method is picked up with no code change here), and a
// descriptor-walking message builder covering scalars, enums (including
// deliberately out-of-range values), repeated fields, maps, oneofs (including
// proto3 "optional" synthetic oneofs), nested messages (bounded recursion), and
// injected unknown fields.

import (
	"math"
	"sort"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
)

// fuzzCursor is a deterministic, never-exhausted byte reader: once the backing
// slice runs out, every further read returns zero instead of panicking or
// blocking, so buildMessage always terminates and the same input always
// produces the same message (required for corpus replay).
type fuzzCursor struct {
	data []byte
	pos  int
}

func newFuzzCursor(data []byte) *fuzzCursor { return &fuzzCursor{data: data} }

func (c *fuzzCursor) byte() byte {
	if c.pos >= len(c.data) {
		return 0
	}
	b := c.data[c.pos]
	c.pos++
	return b
}

func (c *fuzzCursor) bytesN(n int) []byte {
	if n <= 0 {
		return nil
	}
	out := make([]byte, n)
	for i := range out {
		out[i] = c.byte()
	}
	return out
}

func (c *fuzzCursor) u32() uint32 {
	return uint32(c.byte()) | uint32(c.byte())<<8 | uint32(c.byte())<<16 | uint32(c.byte())<<24
}

func (c *fuzzCursor) u64() uint64 {
	return uint64(c.u32()) | uint64(c.u32())<<32
}

// interestingInt64s / interestingUint64s / interestingFloats are boundary
// values worth hitting deliberately (zero, sign flips, type-width edges)
// alongside pure byte-driven values -- a mix of structured and arbitrary input,
// the same idea FuzzGRPCRESTSecretReadAuthzParity's program bytes use for
// control flow, applied here to scalar field VALUES.
var (
	interestingInt64s   = []int64{0, 1, -1, 2, -2, 1<<31 - 1, -(1 << 31), 1<<63 - 1, -(1 << 63), 100, -100}
	interestingUint64s  = []uint64{0, 1, 2, 1<<32 - 1, 1<<64 - 1, 1000}
	interestingFloats64 = []float64{0, 1, -1, 1e300, -1e300, 1e-300}
)

func (c *fuzzCursor) int64Value() int64 {
	if c.byte()%4 == 0 {
		return interestingInt64s[int(c.byte())%len(interestingInt64s)]
	}
	return int64(c.u64())
}

func (c *fuzzCursor) uint64Value() uint64 {
	if c.byte()%4 == 0 {
		return interestingUint64s[int(c.byte())%len(interestingUint64s)]
	}
	return c.u64()
}

func (c *fuzzCursor) floatValue() float64 {
	switch c.byte() % 8 {
	case 0:
		return interestingFloats64[int(c.byte())%len(interestingFloats64)]
	case 1:
		return math.NaN()
	case 2:
		return math.Inf(1)
	case 3:
		return math.Inf(-1)
	default:
		return float64(int64(c.u64())) / 1000.0
	}
}

// sizeProbe decides, for a variable-length value (string/bytes/repeated/map),
// between an ordinary small size (the common case, keeps throughput high) and
// an occasional much larger one -- the latter is what gives the bounded-work
// oracle (checkBoundedWork) something genuinely proportional to test against,
// and what gives Go's coverage-guided mutator corpus entries worth growing
// further. Capped well under the gRPC transport's configured message-size
// limit so a "too large" rejection at the transport layer doesn't masquerade
// as this harness's own size probing.
func (c *fuzzCursor) sizeProbe(smallMax, largeMax int) int {
	if c.byte()%16 == 0 {
		n := min(int(c.byte())<<8|int(c.byte()), largeMax)
		return n
	}
	return int(c.byte()) % (smallMax + 1)
}

func (c *fuzzCursor) stringValue() string {
	n := c.sizeProbe(48, 65536)
	raw := c.bytesN(n)
	// proto3 string fields require valid UTF-8; strip invalid sequences rather
	// than reject the raw bytes outright, so garbage input still exercises
	// string-handling code paths instead of failing to marshal at all.
	return strings.ToValidUTF8(string(raw), "")
}

func (c *fuzzCursor) bytesValue() []byte {
	n := c.sizeProbe(48, 65536)
	return c.bytesN(n)
}

// smallCount sizes a repeated/map field's element count.
func (c *fuzzCursor) smallCount() int {
	return c.sizeProbe(5, 2000)
}

// maxBuildDepth bounds buildMessage's own recursion into nested messages --
// independent of the bounded-work oracle (which bounds the SERVER's handling
// time), this is hygiene for the BUILDER itself against a pathological or
// future recursive message schema.
const maxBuildDepth = 6

// buildMessage walks desc's fields and populates a fresh dynamicpb message
// driven entirely by c. Every kind of field this proto schema can declare is
// handled generically via the descriptor, not by name -- a new field or a new
// message type in keyorix.proto is covered automatically, no change needed
// here.
func buildMessage(desc protoreflect.MessageDescriptor, c *fuzzCursor, depth int) *dynamicpb.Message {
	msg := dynamicpb.NewMessage(desc)
	if depth >= maxBuildDepth {
		return msg
	}
	fields := desc.Fields()
	handledOneof := map[protoreflect.Name]bool{}
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if oo := fd.ContainingOneof(); oo != nil && !oo.IsSynthetic() {
			// A REAL oneof (not a proto3 "optional" field's synthetic one): at most
			// one member field may be set. Decide once per oneof, the first time any
			// of its member fields is encountered.
			if handledOneof[oo.Name()] {
				continue
			}
			handledOneof[oo.Name()] = true
			ooFields := oo.Fields()
			pick := int(c.byte()) % (ooFields.Len() + 1) // +1 == "set none of them"
			if pick == ooFields.Len() {
				continue
			}
			setField(msg, ooFields.Get(pick), c, depth)
			continue
		}
		// Ordinary field (including a synthetic-oneof / proto3 "optional" field,
		// which behaves like an independent presence bit): skip roughly a third of
		// the time so explicit-absence / zero-value code paths get exercised too,
		// not just "every field populated".
		if c.byte()%3 == 0 {
			continue
		}
		setField(msg, fd, c, depth)
	}
	maybeInjectUnknownField(msg, c)
	return msg
}

func setField(msg *dynamicpb.Message, fd protoreflect.FieldDescriptor, c *fuzzCursor, depth int) {
	switch {
	case fd.IsMap():
		setMapField(msg, fd, c, depth)
	case fd.IsList():
		setListField(msg, fd, c, depth)
	default:
		msg.Set(fd, scalarValue(fd, c, depth))
	}
}

func setListField(msg *dynamicpb.Message, fd protoreflect.FieldDescriptor, c *fuzzCursor, depth int) {
	lst := msg.Mutable(fd).List()
	n := c.smallCount()
	for range n {
		lst.Append(scalarValue(fd, c, depth+1))
	}
}

func setMapField(msg *dynamicpb.Message, fd protoreflect.FieldDescriptor, c *fuzzCursor, depth int) {
	mp := msg.Mutable(fd).Map()
	n := c.smallCount()
	keyFd, valFd := fd.MapKey(), fd.MapValue()
	for range n {
		k := scalarValue(keyFd, c, depth+1).MapKey()
		v := scalarValue(valFd, c, depth+1)
		mp.Set(k, v)
	}
}

// scalarValue produces one value for fd (a plain scalar, an enum, or -- when
// called for a list/map element or a nested message field -- recurses via
// buildMessage). Covers every protoreflect.Kind proto3 can declare.
func scalarValue(fd protoreflect.FieldDescriptor, c *fuzzCursor, depth int) protoreflect.Value {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(c.byte()%2 == 0)
	case protoreflect.EnumKind:
		vals := fd.Enum().Values()
		if vals.Len() > 0 && c.byte()%4 != 0 {
			return protoreflect.ValueOfEnum(vals.Get(int(c.byte()) % vals.Len()).Number())
		}
		// Deliberately out-of-range: exercises this field's unknown-enum-value handling.
		return protoreflect.ValueOfEnum(protoreflect.EnumNumber(int32(c.u32())))
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return protoreflect.ValueOfInt32(int32(c.int64Value()))
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(uint32(c.uint64Value()))
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64(c.int64Value())
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(c.uint64Value())
	case protoreflect.FloatKind:
		return protoreflect.ValueOfFloat32(float32(c.floatValue()))
	case protoreflect.DoubleKind:
		return protoreflect.ValueOfFloat64(c.floatValue())
	case protoreflect.StringKind:
		return protoreflect.ValueOfString(c.stringValue())
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes(c.bytesValue())
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return protoreflect.ValueOfMessage(buildMessage(fd.Message(), c, depth+1))
	default:
		return fd.Default()
	}
}

// unknownFieldBase is chosen well above every field number keyorix.proto
// declares or reserves (its highest reservation is in the low hundreds), so an
// injected field is unambiguously NOT one this schema defines.
const unknownFieldBase = 90000

// maybeInjectUnknownField appends a syntactically valid but schema-unknown
// field to msg about a quarter of the time, exercising the "unknown fields"
// requirement from the session spec: a real client speaking a newer/older
// wire schema can send fields this server build doesn't know about, and the
// server must tolerate (ignore) them, not choke.
func maybeInjectUnknownField(msg *dynamicpb.Message, c *fuzzCursor) {
	if c.byte()%4 != 0 {
		return
	}
	num := protowire.Number(unknownFieldBase + int(c.byte()))
	var raw []byte
	switch c.byte() % 4 {
	case 0:
		raw = protowire.AppendVarint(protowire.AppendTag(nil, num, protowire.VarintType), c.uint64Value())
	case 1:
		raw = protowire.AppendFixed32(protowire.AppendTag(nil, num, protowire.Fixed32Type), uint32(c.uint64Value()))
	case 2:
		raw = protowire.AppendFixed64(protowire.AppendTag(nil, num, protowire.Fixed64Type), c.uint64Value())
	default:
		payload := c.bytesN(int(c.byte()) % 32)
		raw = protowire.AppendBytes(protowire.AppendTag(nil, num, protowire.BytesType), payload)
	}
	msg.SetUnknown(append(msg.GetUnknown(), raw...))
}

// grpcMethod names one discovered unary RPC and its descriptor-level input/
// output types.
type grpcMethod struct {
	serviceFull string
	methodName  string
	input       protoreflect.MessageDescriptor
	output      protoreflect.MessageDescriptor
}

func (m grpcMethod) fullMethod() string { return "/" + m.serviceFull + "/" + m.methodName }
func (m grpcMethod) key() string        { return m.serviceFull + "/" + m.methodName }

// discoverUnaryMethods asks the live *grpc.Server which services it actually
// registered (GetServiceInfo), then resolves each one's protoreflect
// descriptor from the global registry (populated by server/proto/pb's own
// init()) to enumerate its methods. Driven by the server's live registration,
// not a hand-maintained service/method list: a service NewServer stops
// registering disappears from here automatically, and one it starts
// registering appears without any change to this file. Streaming RPCs
// (StreamAuditLogs) are excluded -- this mutator targets unary request/response
// calls; a streaming-specific harness is a separate, future target, and the
// coverage report this fuzzer prints names it as a known, intentional gap.
func discoverUnaryMethods(srv *grpc.Server) []grpcMethod {
	info := srv.GetServiceInfo()
	names := make([]string, 0, len(info))
	for n := range info {
		names = append(names, n)
	}
	sort.Strings(names) // deterministic ordering: GetServiceInfo's map iteration is not.

	var methods []grpcMethod
	for _, svcName := range names {
		d, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(svcName))
		if err != nil {
			continue
		}
		sd, ok := d.(protoreflect.ServiceDescriptor)
		if !ok {
			continue
		}
		mds := sd.Methods()
		for i := 0; i < mds.Len(); i++ {
			md := mds.Get(i)
			if md.IsStreamingClient() || md.IsStreamingServer() {
				continue
			}
			methods = append(methods, grpcMethod{
				serviceFull: svcName,
				methodName:  string(md.Name()),
				input:       md.Input(),
				output:      md.Output(),
			})
		}
	}
	return methods
}

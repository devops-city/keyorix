// Package gcpsource reads secrets from GCP Secret Manager. AccessSecretVersion read logic
// (empty-value rejection, gRPC response-size cap) is ported from internal/connect/gcpsm.go —
// migrate cannot import internal/connect (module boundary, docs/design-keyorix-migrate.md) —
// but this package additionally LISTS every secret in the project (paginated) and checks each
// secret's latest-version state, which gcpsm.go's single-ref GetSecret never needed to do.
package gcpsource

import (
	"context"
	"fmt"
	"strings"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	gax "github.com/googleapis/gax-go/v2"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/migrate/internal/cloudentry"
	"github.com/keyorixhq/keyorix/migrate/internal/splitjson"
)

// gcpMaxRecvMsgSize caps how large a single gRPC response this connector will accept, matching
// internal/connect/gcpsm.go's own constant and rationale: the SDK's own default
// (grpc.MaxCallRecvMsgSize(math.MaxInt32), confirmed by reading it directly) is effectively no
// cap at all. GCP Secret Manager's documented maximum secret payload is 64 KiB; 1 MiB leaves
// generous headroom for protocol/gRPC framing overhead.
const gcpMaxRecvMsgSize = 1 << 20 // 1 MiB

// Config holds every GCP Secret Manager setting a Client needs. Credentials always come from
// Application Default Credentials (ADC) / the workload identity — never a Keyorix config field
// or CLI flag, matching internal/connect/gcpsm.go's precedent.
type Config struct {
	// ProjectID is required -- every list/read call is scoped to exactly this project, mirroring
	// internal/connect/gcpsm.go's own project_id being a REQUIRED (not optional) binding for the
	// same confused-deputy reason documented there: a GCP secret-version resource name carries
	// its own project ID, so without a pin this client would address whatever project the ADC
	// identity can reach.
	ProjectID  string
	NamePrefix string // optional; only secret short names with this prefix are imported.
	// SplitJSON imports each top-level key of a JSON-object secret value as its own Keyorix
	// secret (Name field <secret>-<key>) instead of the whole string as one secret.
	SplitJSON bool
}

// secretLister is the narrow slice of *secretmanager.SecretIterator this package needs — an
// interface seam (rather than depending on the concrete iterator type directly) so ListSecrets
// is unit-tested with a fake.
type secretLister interface {
	Next() (*secretmanagerpb.Secret, error)
}

// gcpAPI is the slice of the Secret Manager client this package uses — an interface seam so it
// is unit-tested with a fake, matching internal/connect/gcpsm.go's gcpSMAccessAPI precedent
// (extended here with ListSecrets/GetSecretVersion, which that single-ref connector never
// needed).
type gcpAPI interface {
	ListSecrets(ctx context.Context, req *secretmanagerpb.ListSecretsRequest, opts ...gax.CallOption) secretLister
	GetSecretVersion(ctx context.Context, req *secretmanagerpb.GetSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.SecretVersion, error)
	AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
	Close() error
}

// realClient adapts *secretmanager.Client to gcpAPI — the only reason this adapter exists is
// ListSecrets: the real client returns the concrete *secretmanager.SecretIterator, which this
// package narrows to the secretLister interface so tests can supply a fake.
type realClient struct{ cl *secretmanager.Client }

func (r realClient) ListSecrets(ctx context.Context, req *secretmanagerpb.ListSecretsRequest, opts ...gax.CallOption) secretLister {
	return r.cl.ListSecrets(ctx, req, opts...)
}
func (r realClient) GetSecretVersion(ctx context.Context, req *secretmanagerpb.GetSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.SecretVersion, error) {
	return r.cl.GetSecretVersion(ctx, req, opts...)
}
func (r realClient) AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	return r.cl.AccessSecretVersion(ctx, req, opts...)
}
func (r realClient) Close() error { return r.cl.Close() }

// Client lists and reads secrets from GCP Secret Manager.
type Client struct {
	cfg Config
	// newClient builds a gcpAPI; nil uses the real client (ADC). Tests inject a fake.
	newClient func(ctx context.Context) (gcpAPI, error)
}

// New builds a Client. It performs no network call — credential/project problems surface
// clearly at the first real call instead.
func New(cfg Config) *Client {
	return &Client{cfg: cfg}
}

func (c *Client) client(ctx context.Context) (gcpAPI, error) {
	if c.newClient != nil {
		return c.newClient(ctx)
	}
	if c.cfg.ProjectID == "" {
		return nil, fmt.Errorf("gcp-secret-manager: project ID is required")
	}
	cl, err := secretmanager.NewClient(ctx, option.WithGRPCDialOption(
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(gcpMaxRecvMsgSize)),
	))
	if err != nil {
		return nil, fmt.Errorf("gcp-secret-manager: new client: %w", err)
	}
	return realClient{cl: cl}, nil
}

// List lists every secret in the project (optionally restricted to short names with
// cfg.NamePrefix), reads each enabled one's current (latest) value, and returns it as a
// cloudentry.Entry — or, when a secret can't or shouldn't be imported (disabled, destroyed, no
// versions, no value, or a read error), as a cloudentry.Skipped with a reason. Matches
// awssource/azuresource's "report, don't drop" convention.
func (c *Client) List(ctx context.Context) ([]cloudentry.Entry, []cloudentry.Skipped, error) {
	cl, err := c.client(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = cl.Close() }()

	var entries []cloudentry.Entry
	var skipped []cloudentry.Skipped
	it := cl.ListSecrets(ctx, &secretmanagerpb.ListSecretsRequest{Parent: "projects/" + c.cfg.ProjectID})
	for {
		secret, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("gcp-secret-manager: list secrets: %w", err)
		}
		name := gcpShortName(secret.GetName())
		if name == "" {
			continue
		}
		if c.cfg.NamePrefix != "" && !strings.HasPrefix(name, c.cfg.NamePrefix) {
			continue
		}
		locator := c.locator(name)

		latestName := secret.GetName() + "/versions/latest"
		ver, err := cl.GetSecretVersion(ctx, &secretmanagerpb.GetSecretVersionRequest{Name: latestName})
		if err != nil {
			if status.Code(err) == codes.NotFound {
				skipped = append(skipped, cloudentry.Skipped{Locator: locator, Reason: "secret has no versions"})
				continue
			}
			return nil, nil, fmt.Errorf("gcp-secret-manager: get latest version metadata for %q: %w", name, err)
		}
		// The "disabled/destroyed secret" case: checked from the version's own state metadata,
		// never inferred from an AccessSecretVersion failure — a disabled version's access call
		// fails with FAILED_PRECONDITION, which would otherwise be indistinguishable from a
		// genuine backend error without this explicit check.
		switch ver.GetState() {
		case secretmanagerpb.SecretVersion_DISABLED:
			skipped = append(skipped, cloudentry.Skipped{Locator: locator, Reason: "latest version is disabled"})
			continue
		case secretmanagerpb.SecretVersion_DESTROYED:
			skipped = append(skipped, cloudentry.Skipped{Locator: locator, Reason: "latest version was destroyed"})
			continue
		}

		es, skip, err := c.readSecret(ctx, cl, name, latestName, ver, locator)
		if err != nil {
			return nil, nil, err
		}
		if skip != nil {
			skipped = append(skipped, *skip)
			continue
		}
		entries = append(entries, es...)
	}
	return entries, skipped, nil
}

func (c *Client) locator(name string) string {
	return fmt.Sprintf("gcp-secret-manager:%s/%s", c.cfg.ProjectID, name)
}

// readSecret fetches one secret's latest-version value and turns it into one or more
// cloudentry.Entry (more than one only when SplitJSON explodes a JSON object), or a Skipped
// with a reason. ver is the already-fetched SecretVersion metadata (its own resolved Name
// carries the real numeric version, unlike latestName's "latest" alias).
func (c *Client) readSecret(ctx context.Context, cl gcpAPI, name, latestName string, ver *secretmanagerpb.SecretVersion, locator string) ([]cloudentry.Entry, *cloudentry.Skipped, error) {
	out, err := cl.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{Name: latestName})
	if err != nil {
		return nil, nil, fmt.Errorf("gcp-secret-manager: access %q: %w", name, err)
	}
	if out.GetPayload() == nil || len(out.GetPayload().GetData()) == 0 {
		return nil, &cloudentry.Skipped{Locator: locator, Reason: "secret has no value"}, nil
	}

	value := string(out.GetPayload().GetData())
	version := gcpVersionID(ver.GetName())
	createdAt := ""
	if ver.GetCreateTime() != nil {
		createdAt = ver.GetCreateTime().AsTime().UTC().Format(time.RFC3339)
	}

	if c.cfg.SplitJSON {
		if fields, ok := splitjson.Object(value); ok {
			entries := make([]cloudentry.Entry, 0, len(fields))
			for _, f := range fields {
				entries = append(entries, cloudentry.Entry{
					RawName:   name,
					Field:     f.Key,
					Value:     f.Value,
					Version:   version,
					CreatedAt: createdAt,
					Locator:   locator + "#" + f.Key,
				})
			}
			if len(entries) > 0 {
				return entries, nil, nil
			}
		}
	}
	return []cloudentry.Entry{{RawName: name, Value: value, Version: version, CreatedAt: createdAt, Locator: locator}}, nil, nil
}

// gcpShortName extracts NAME from a Secret resource name ("projects/P/secrets/NAME").
func gcpShortName(resourceName string) string {
	const marker = "/secrets/"
	_, after, ok := strings.CutLast(resourceName, marker)
	if !ok {
		return ""
	}
	return after
}

// gcpVersionID extracts the numeric version ID from a resolved SecretVersion resource name
// ("projects/P/secrets/NAME/versions/N").
func gcpVersionID(resourceName string) string {
	const marker = "/versions/"
	_, after, ok := strings.CutLast(resourceName, marker)
	if !ok {
		return ""
	}
	return after
}

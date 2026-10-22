### Internal
- **`compliance verify` uses the typed API client.** The OpenAPI schema already lists the required `filename` field of `POST /api/v1/compliance/evidence/verify`, so the CLI now sends it through the generated request body instead of hand-built raw JSON.

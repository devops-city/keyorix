### Security
- **`admin restore` checks secret references against the right table (#3078).** backupfmt classified
  the `secret_id` column of `share_records`, `secret_acls`, `access_requests`,
  `secret_version_comments` and `access_review_items` as a reference to `mfa_secrets`, because there
  is no `Secret` model and the naming convention also matched a model name that merely *ends* in the
  field's name. Restore's mandatory dangling-reference check therefore refused a valid backup holding
  a share, ACL or access request on a real secret (unless an MFA secret had the same id), and accepted
  a reference to a secret that does not exist whenever an MFA secret had that id. The five columns now
  reference `secret_nodes`, and the convention only matches a field that ends with a model's full name;
  anything else must be listed in `referenceOverrides` by hand (the three `ClientID -> APIClient`
  fields now are). Existing backup archives need no conversion.

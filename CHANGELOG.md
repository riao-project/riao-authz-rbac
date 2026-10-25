# auth-template - Changelog

## 3.0.0

- Require IAM 5, REST 3, and api-machine 2.
- Accept trusted ID-only authorization subjects across evaluation helpers.
- Propagate policy-store failures rather than returning exception-bearing
  denial results; reject unsupported object-resource policy input explicitly.
- Verify real OAuth2 driver tokens through REST/RBAC HTTP enforcement.
- Configure OAuth2 integration directly through API Machine's bearer callback.

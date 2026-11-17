# Evidence policy authority boundary

Core owns canonical application identity, organization, ownership and approval
policy selection. External connectors submit normalized evidence through the
public Common Gateway. They must not invoke private Core endpoints, access a
platform database or supply policy text as an integration shortcut.

The `marty-verification::evidence_policy` module is a computation kernel, not an
authentication or transport boundary. Its JSON/Python entry points do not establish
where supplied records came from. Platform adapters must obtain the application,
current evidence and selected PolicySet from canonical records within the
application's organization, after the public Gateway has enforced authentication
and authorization. A matching PolicySet ID is necessary but does not establish
tenant provenance by itself.

## Approval is explicit

The bundled approval set grants no permits. Verified evidence, a connector name,
a binding flag or a complete requirement summary does not independently authorize
approval. An explicit active `APPROVAL_RULES` or `CUSTOM` PolicySet remains the
platform owner's authority. Missing, mismatched, inactive, wrong-type, empty and
malformed policy configuration fails closed. Approval policy evaluation remains
separate from broad Gateway RBAC permits.

The evaluator uses one fixed `platform-evidence-policy` principal. This is an
internal evaluation identity, not a connector credential. Provider and fact-type
identifiers remain opaque data for explicit matching; they confer no authority.

No provider-specific requirement is inferred. With no required requirements, the
summary reports zero required/satisfied, false `all_required_evidence_satisfied`
and false `auto_issue_eligible`. No provider is inferred from absent facts.
Document-verification, biometric, risk and country observations are absent when
not supplied by an implemented canonical source; the kernel does not fabricate
successful observations. Policies referring to unavailable attributes deny.

## Requirement contract

Requirements are nonempty fact-type strings or objects with these keys:
`requirement_id`, `provider`, `source`, `fact_type`, `evidence_type`, `type`,
`verification_method`, `scope`, `pass_rule`, `required`, `auto_issue_on_permit`.
Unknown keys reject before policy evaluation, including if an explicit policy
would otherwise permit. Supplied `scope` and `pass_rule` values must be objects. Selectors must be
strings; `required` and `auto_issue_on_permit` must be booleans. Invalid types
reject instead of coercing a constraint to a wildcard or a truthy flag.
Use only the generic `scope` field; obsolete constraint aliases are rejected
instead of becoming unconstrained matches. Existing provider/fact strings are
not rewritten or assigned new meanings by the kernel.

## Deferred work

- Platform policy owner: define and review real approval policies and canonical
  observation inputs before enabling automatic issuance.
- Gateway/application owner: verify authenticated tenant-scoped record retrieval
  and original-operation behavior for each exposed evidence contract.
- Connector owner: leave unsupported workflows disabled with owned TODOs until
  the necessary public Gateway contracts exist. Production adapter completeness
  and deployed qualification are separate from repository boundary cleanup.

Local module tests cover default denial, configured positive/negative evidence
matching, revision selection, PolicySet selection failures, absent observations,
retired/malformed constraints and preservation of opaque provider identifiers.
They do not qualify deployed authentication or tenant provenance.

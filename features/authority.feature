@specified @m1_fixture_bound @local_simulation @authority
Feature: Policy grants narrow and currently valid authority
  Background:
    Given agent "agent-a" is active
    And "skill-v1" has an eligible qualification for registry "registry-a" in environment "demo-a"
    And no permission exists before an explicit policy decision

  @BDD-008
  Scenario: Policy approval issues authority bound to its qualifying evidence
    Given policy "auth-policy-v1" permits only "release" on "registry-a/model-a" in "demo-a"
    When a 300-second grant is requested for that exact qualification
    Then the issued grant binds the agent, skill revision, qualification ID, and policy revision
    And its command contract binds exact skill, context, qualification, and policy digests
    And it identifies the monotonic current authority revision
    And the grant permits only "release" on "registry-a/model-a" in "demo-a"
    And its validity does not exceed the requested 300 seconds or qualification validity
    And the independently verified evidence references remain resolvable

  @BDD-009
  Scenario: Qualification cannot override a policy denial
    Given policy "auth-policy-v1" denies release during the requested window
    When a grant is requested for the eligible qualification
    Then the request is DENIED
    And no active grant is created
    And the qualification remains eligible for a later policy evaluation

  @BDD-010
  Scenario Outline: The next mutation is refused outside the exact grant
    Given an active grant permits "release" on "registry-a/model-a" in "demo-a" for "skill-v1"
    When an attempt requests "<action>" on "<resource>" in "<context>" using "<revision>"
    Then the execution boundary denies the mutation
    And an independent registry read confirms no state change

    Examples:
      | case             | action  | resource           | context | revision |
      | wrong-action     | delete  | registry-a/model-a | demo-a  | skill-v1 |
      | wrong-resource   | release | registry-a/model-b | demo-a  | skill-v1 |
      | wrong-context    | release | registry-a/model-a | demo-b  | skill-v1 |
      | changed-revision | release | registry-a/model-a | demo-a  | skill-v2 |

  @BDD-011
  Scenario: A passport expires at its boundary instant
    Given the grant's passport expires at controlled time "T"
    When a mutation is evaluated at time "T"
    Then the execution boundary denies the mutation with reason EXPIRED_PASSPORT
    And an independent registry read confirms no state change

  @BDD-012
  Scenario: A scope can expire before its containing passport
    Given the passport remains valid for 300 seconds
    And the requested scope expires after 60 seconds
    When that scope is used at elapsed time 60 seconds
    Then the execution boundary denies the mutation with reason EXPIRED_SCOPE
    And an independent registry read confirms no state change

  @BDD-013
  Scenario: Explicit revocation invalidates a previously successful check
    Given a grant passed admission before revocation
    And the authoritative service has since acknowledged that grant's revocation
    When the admitted attempt reaches the registry mutation boundary
    Then the execution boundary denies the mutation with reason REVOKED_AUTHORITY
    And an independent registry read confirms no state change
    And enforcement uses a mutation fence rather than only a prior status check

  @BDD-014
  Scenario: Missing or unparseable validity data cannot create authority
    Given a passport response has an absent or invalid expiry timestamp
    When the adapter validates the response for execution
    Then the response is rejected as INVALID_AUTHORITY
    And no executable grant is cached

  @BDD-015
  Scenario: Authority checks cannot succeed using stale cached status alone
    Given a locally cached grant is marked active
    And the authoritative current-status service is unavailable
    When a new registry mutation is attempted
    Then the mutation is HELD with reason AUTHORITY_UNCONFIRMED
    And an independent registry read confirms no state change

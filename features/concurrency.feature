@specified @m1_fixture_bound @local_simulation @concurrency
Feature: Concurrent changes have a single auditable authority order
  These scenarios use deterministic interleaving hooks. A revocation takes effect
  at its authoritative commit; it does not retroactively undo a prior mutation.

  @BDD-028
  Scenario: Concurrent issuance cannot produce two effective current passports
    Given two requests both observed authority revision 4 for the same agent
    When they concurrently request different replacement passports
    Then only one request can commit a transition from revision 4
    And the other receives a conflict or reevaluates against the committed revision
    And exactly one passport revision is effective
    And every acknowledged grant is represented in that effective revision

  @BDD-029
  Scenario: Acknowledged revocation wins over an uncommitted registry mutation
    Given an attempt passed admission under authority revision 4
    And the attempt pauses before the registry commit boundary
    When revocation commits authority revision 5 and is acknowledged
    And the attempt resumes
    Then the registry refuses the revision-4 mutation
    And an independent registry read confirms no state change

  @BDD-030
  Scenario: A mutation committed before revocation remains a completed attempt
    Given a mutation committed under authority revision 4
    When revocation then commits authority revision 5
    Then the prior attempt remains recorded as committed before revocation
    And its independent outcome still must be established
    And the next mutation under revision 4 is denied
    And the evidence does not claim revocation undid the prior mutation

  @BDD-031
  Scenario: A stale scope update cannot restore a concurrently revoked grant
    Given an updater read a passport containing "release-model" and "read-health" at revision 4
    And another request revoked "release-model" at revision 5
    When the updater submits its revision-4 replacement adding another "read-health" resource
    Then that stale replacement cannot commit as current authority
    And any recomputed replacement preserves the release revocation
    And the unaffected read-health grants remain available

  @BDD-032
  Scenario: Concurrent duplicate attempts cause one mutation
    Given two transport requests carry the same attempt ID and payload digest
    When they reach the registry concurrently under valid authority
    Then at most one registry mutation commits
    And both requests resolve to the same durable attempt result
    And only one attempt contributes to qualification evidence

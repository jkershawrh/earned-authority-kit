@specified @m1_fixture_bound @local_simulation @ledger
Feature: Evidence remains attributable and cannot silently authorize replay
  Background:
    Given the local kit requires a durable authenticated local intent and outbox record before mutation
    And the local kit does not require a remote ledger receipt before mutation
    And receipt verification checks content, signer trust, attempt binding, and freshness
    And hash-chain integrity alone does not establish an assertion's truth

  @BDD-033
  Scenario Outline: A local intent that cannot be durably authenticated blocks mutation
    Given no durable authenticated local intent exists for "attempt-1"
    And persisting its local intent fails because "<cause>"
    When "attempt-1" reaches the execution boundary
    Then the attempt is DENIED with reason "<reason>"
    And an independent registry read confirms no state change

    Examples:
      | case               | cause                            | reason                          |
      | local-store-down   | local durable storage is offline | LOCAL_DURABILITY_UNAVAILABLE    |
      | unauthenticated    | local writer authentication fails| LOCAL_INTENT_UNAUTHENTICATED    |

  @BDD-034
  Scenario Outline: Remote ledger outage keeps outcomes distinct from delivery state
    Given the authenticated intent for "attempt-1" is durable in the local outbox
    And authority for "attempt-1" remains valid at the registry commit boundary
    And the remote ledger outage begins "<outage_point>"
    When the mutation commits and the independent checker confirms its required postcondition
    Then "attempt-1" remains recorded as committed with evidence delivery pending
    And the independent outcome remains PASS
    And no remote ledger receipt is fabricated
    And the exact outcome record is retained in a durable retry buffer
    And the remote outage alone does not hold qualification or revoke otherwise valid authority
    And recovery reconciles actual registry state before any execution retry
    And recovery retries evidence delivery without repeating the registry mutation
    And duplicate ledger deliveries cannot create a second qualification outcome

    Examples:
      | case                | outage_point                      |
      | before-intent-send  | before remote intent delivery     |
      | after-commit        | after commit before outcome delivery |

  @BDD-035
  Scenario: Modified evidence cannot pass receipt verification
    Given a valid receipt binds an outcome's content digest
    When the stored outcome payload is altered without a matching valid receipt
    Then evidence verification reports TAMPER_DETECTED
    And the altered outcome is excluded from qualification
    And affected authority is HELD for review

  @BDD-036
  Scenario Outline: Evidence from another purpose cannot authorize a current attempt
    Given an otherwise valid receipt belongs to "<receipt_binding>"
    When it is offered as evidence for "attempt-current" and its current skill revision
    Then the evidence is rejected with reason "<reason>"
    And no new mutation is authorized by that receipt

    Examples:
      | case          | receipt_binding            | reason                 |
      | other-attempt | a different attempt ID     | ATTEMPT_MISMATCH       |
      | old-skill     | an earlier skill revision  | SKILL_REVISION_MISMATCH |
      | expired-proof | an expired evidence window | STALE_EVIDENCE         |

  @BDD-037
  Scenario: An intact chain from an untrusted evidence signer is insufficient
    Given an outcome record is on an intact ledger chain
    And its signer is not trusted to attest independent outcomes
    When qualification evaluates that outcome
    Then the outcome is excluded with reason UNTRUSTED_ATTESTATION
    And no qualification pass is counted
    And no grant is issued from that assertion

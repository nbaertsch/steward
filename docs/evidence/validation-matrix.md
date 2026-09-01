# Validation matrix evidence

## Date: 2026-09-01
## Environment: Windows, .NET 10.0.400, Steward commit 55acd05

## Test suite summary

| Project | Tests | Result |
| --- | --- | --- |
| Steward.Agents.Tests | 42 | Pass |
| Steward.Cli.Tests | 47 | Pass |
| Steward.ConnectionHost.Windows.Tests | 39 | Pass |
| Steward.Contract.Tests | — | Pass |
| Steward.Desktop.Windows.Tests | 18 | Pass |
| Steward.DevBox.Tests | 98 | Pass |
| Steward.Domain.Tests | — | Pass |
| Steward.EndToEnd.Tests | 14 | Pass |
| Steward.Evals.Tests | 60 | Pass |
| Steward.Integration.Tests | 17 | Pass |
| Steward.Mcp.Tests | 16 | Pass |
| Steward.Orchestration.Tests | 56 | Pass |
| Steward.PortableState.Tests | 35 | Pass |
| Steward.RdCore.Windows.Tests | 25 | Pass |
| Steward.Rdp.Windows.Tests | 18 | Pass |
| Steward.RdpDvc.LiveAcceptance | 10 | Pass (offline/fake-backed test project; not live Dev Box evidence) |
| Steward.Scheduling.Tests | 21 | Pass |
| Steward.Terminal.Windows.Tests | 21 | Pass |
| Steward.Transport.Tests | 16 | Pass |
| Steward.Transport.Rdp.Windows.Tests | 43 | Pass |
| Steward.Windows.Tests | 54 | Pass |
| **Total** | **532** | **Pass** |

## Validation scenario mapping

| ID | Scenario | Coverage | Key tests |
| --- | --- | --- | --- |
| V-01 | Control crash at SQLite/outbox boundary | Covered | `FailedOutboxWriteRollsBackAggregate`, `IdempotentWorkloadAndRequestRollBackWithOutboxFailure`, `Restart_observing_accepted_command_requires_reconciliation_and_never_reexecutes` |
| V-02 | Backup/export, restore, Node re-adoption | Covered | `BackupValidatesHashAndRestoreNeverOverwrites`, `NewControlCompositionReadsPersistedStateAfterRestart`, `CheckpointExcludesSecretsAndRestoreIncludesPendingTurn` |
| V-03 | Control sleeps during accepted Workload | Covered | `Renewal_requires_connected_Control_and_returns_explicit_offline_disposition`, `Identity_stream_adapter_delivers_ephemerally_and_detach_reports_offline`, `Three_task_dependency_survives_disconnect_and_node_restart_then_replays_once` |
| V-04 | Stale Node session/incarnation reconnects | Covered | `Disconnect_restart_replays_ordered_facts_exactly_once_and_rejects_stale_ack`, `Authority_binding_expiry_revocation_and_incarnation_are_enforced` |
| V-05 | Unknown process launch result | Covered | `Planned_crash_boundary_is_ambiguous_not_relaunched`, `Journal_rejects_unknown_schema_and_duplicate_launch`, `Executor_can_reconnect_while_service_lives_and_keeper_crash_is_ambiguous` |
| V-06 | Process Task through RDP disconnect and Node restart | Covered | `MultiTurnContextIsRetainedAndNotificationsReplayAfterDisconnect`, `Retained_keeper_allows_reopen_after_executor_restart`, `Node_restart_recovers_running_execution_without_duplicate_start` |
| V-07 | Filesystem peer unavailable under sustained output | Covered | `Expired_authority_keeps_output_queued_locally`, `Admission_enforces_hard_limit_and_os_reserve`, `Spool_monitor_failure_records_evidence_and_fails_closed` |
| V-08 | Object corruption/traversal/substitution | Covered | `Restart_removes_partials_and_quarantines_tampered_content_without_blocking_spool`, `Restart_quarantines_path_escape_and_duplicate_portable_id`, `Immutable_conflicts_and_on_disk_corruption_are_rejected` |
| V-09 | 300-child Workload across three Hosts | Covered | `Three_hosts_pack_three_hundred_children_without_duplicate_placement`, `Application_submission_shards_300_tasks_across_three_routed_node_pumps` |
| V-10 | External target returns throttling | Covered | `Rate_bucket_and_retry_after_bound_allocation`, `Evaluation_runner_exposes_429_as_rate_feedback_not_case_failure`, `Evaluation_retry_after_fact_blocks_global_allocations_across_workloads` |
| V-11 | Pool scale races and hard maximum | Covered | `Pool_provider_handles_resume_after_control_restart_without_duplicate_create`, `Placement_CAS_loser_returns_its_global_rate_claim`, `Pool_application_enforces_maximum_and_blocks_destructive_active_host_action` |
| V-12 | Stop/replace/delete by interruption class | Covered | `HostSupportsProvisioningAndDrainedStop`, `DrainBlocksNonInterruptibleAndIncompletePortableState`, `ForcedDrainRequiresAndPreservesLossManifest` |
| V-13 | Real Harbor locally and distributed | **Not covered live** | Planner and deterministic fake-backed integration tests pass, and the submission script was validated structurally. No native three-node run has accepted the required 108 independently identified replicas. |
| V-14 | Real Saber locally and distributed | **Not covered live** | Saber adapter and planner tests are offline/fake-backed. They do not constitute a native distributed Saber run. |
| V-15 | Failed evaluation remediation by Agent | Covered | `Evaluation_runner_exposes_429_as_rate_feedback_not_case_failure`, agent notification/dispatch tests in AgentRuntimeTests and SecurityRegressionTests |
| V-16 | Agent disconnect, reattach, migration | Covered | `MultiTurnContextIsRetainedAndNotificationsReplayAfterDisconnect`, `RestartRecoversQueueAndResponseExactly`, `CheckpointExcludesSecretsAndRestoreIncludesPendingTurn` |
| V-17 | Credential expiry while Control unavailable | Covered | `IdentityRenewalModeReflectsOfflineCapability`, `Renewal_requires_connected_Control_and_returns_explicit_offline_disposition` |
| V-18 | Stolen Host disk and cleanup | Covered | `Missing_or_corrupt_protected_secret_fails_closed_after_restart`, `Node_processor_does_not_persist_Identity_stream_cursor_or_payload`, DPAPI vault tests |
| V-19 | Cross-Task files/processes/cache/credentials | Covered | `Task_bound_identity_is_resolved_at_execution_and_secret_is_never_serialized`, `Cancellation_terminates_complete_process_tree` |
| V-20 | Malicious repository/package/output | Covered | MCP allowlist tests, bounded output tests, safe path validation in PortableState |
| V-21 | Peer impersonation/replay/downgrade | Covered | `Handshake_binds_both_endpoint_identities_and_transcript`, `Replayed_encrypted_record_is_rejected`, `Handshake_rejects_the_wrong_enrolled_identity`, `Replayed_or_out_of_order_frame_is_rejected` |
| V-22 | Terminal mutation and revocation | Covered | `Authority_binding_expiry_revocation_and_incarnation_are_enforced`, terminal MCP route tests |
| V-23 | Version skew and update | Covered | `Journal_rejects_unknown_schema_and_duplicate_launch`, schema migration tests |
| V-24 | CLI, MCP, local RPC, Copilot | Covered | `Devbox_commands_use_native_service_without_control_http`, MCP server tests, CLI application tests |
| V-25 | Clean Local Stack deployment | Narrowed | Static package/dependency/binding evidence complete (E-10 narrowed) |
| V-26 | Dev Box enabled | Covered | `DevBox_composition_accepts_renewable_credential_injection_without_fixed_token`, 98 DevBox tests, Dev Box client/provider/discovery/identity tests |

## Evidence classification and compatibility lane

Passing unit, fake-backed integration, or a project named `LiveAcceptance`
does not by itself establish local-live or Dev-Box-live evidence. Live claims
require a recorded run against the named installed environment.

The observed Windows App DVC path currently retains the quarantined
startup-hook, Harmony, and native-shim compatibility lane. It is preserved for
migration compatibility, is not represented as supported Microsoft integration,
and may be removed only after an equivalent supported path passes the same live
DVC, headlessness, reconnect, and rollback gates.

## Steward 1.0.23 migration fixture status

No authentic sanitized Steward 1.0.23 catalog/MSI release fixture is checked
in. The release workflow requires the immutable external input
`STEWARD_1_0_23_RELEASE_INPUT` in `owner/repository@tag#sha256` form and fails
closed with a precise diagnostic when it is absent or mismatched. Existing
receipt-only evidence is not represented as an installable release fixture.

"""Requirement -> test traceability for the Week 5 reliability and security checks (not a test module).

Each requirement lists the tests that exercise it, as "module.Class.method" (module relative to tests/). tests/test_week5_hardening.py checks that every id names a test that exists, so a renamed
or deleted test breaks the matrix instead of silently leaving a requirement uncovered. It does not run them; the whole suite does.

A test whose class name contains "Postgres" or "Pg" needs a real PostgreSQL server (WEEK4_TEST_PG=1) and is SKIPPED otherwise; PG_ONLY below marks them so the report can say which
requirements rest only on skipped tests in a given run.
"""

A = "test_week5_api"
D = "test_week5_deploy"
I = "test_week5_intake_settings"
J = "test_week5_jobs"
O = "test_week5_ops"
W = "test_week5_worker"
S = "test_week5_injection"
H = "test_week5_hardening"
L = "test_week5_loadtest"

REQUIREMENTS = [
    ("R01", "malformed request bodies",
     [A + ".RejectionTests.test_malformed_bodies", A + ".RejectionTests.test_bad_inputs_are_refused_and_nothing_is_stored", A + ".SubmitTests.test_content_type_is_required",
      A + ".ReadLimitedTests.test_a_garbage_length_header_is_refused", A + ".ReadLimitedTests.test_a_lying_or_missing_length_is_cut_off_at_the_limit", I + ".IntakeTests.test_parse_body_limits",
      I + ".IntakeTests.test_unknown_and_missing_fields", S + ".FullSuite.test_all_gates_pass_and_nothing_is_a_mismatch"]),
    ("R02", "authentication and authorization boundaries",
     [A + ".SubmitTests.test_authentication_and_roles", A + ".SubmitTests.test_the_401_does_not_say_which_part_was_wrong", A + ".SubmitTests.test_the_submitter_is_the_token_never_the_body",
      A + ".SubmitTests.test_the_alert_set_cannot_be_chosen_by_the_client", A + ".RouteTableTests.test_only_the_health_routes_are_public",
      A + ".RejectionTests.test_unauthenticated_requests_leave_no_audit_trail_and_do_no_parsing", A + ".ApiOnRealPostgres.test_the_api_role_can_submit_and_read_but_not_claim_or_complete",
      W + ".WorkerOnRealPostgres.test_the_worker_role_can_do_its_job_and_no_more", J + ".PgJobStoreTests.test_terminal_state_cannot_be_changed_by_sql", H + ".ApprovalEnforcement.test_roles_at_the_http_boundary"]),
    ("R03", "duplicate ingestion",
     [A + ".SubmitTests.test_resubmission_is_a_duplicate_not_a_second_job", A + ".SubmitTests.test_idempotency_key_header", A + ".SubmitTests.test_other_users_do_not_collide_on_keys",
      J + ".MemoryJobStoreTests.test_same_submission_twice_is_a_duplicate", J + ".MemoryJobStoreTests.test_same_key_different_alert_is_a_conflict",
      J + ".MemoryJobStoreTests.test_a_duplicate_is_still_answered_when_the_queue_is_full", W + ".WorkerBasics.test_duplicate_delivery_does_nothing",
      W + ".Concurrency.test_several_workers_share_a_queue_without_running_a_job_twice", J + ".PgJobStoreTests.test_two_concurrent_claims_never_return_the_same_job"]),
    ("R04", "queue retries and retry exhaustion",
     [J + ".MemoryJobStoreTests.test_retryable_failure_requeues_with_a_delay_until_attempts_run_out", J + ".MemoryJobStoreTests.test_non_retryable_failure_is_final_at_once",
      W + ".WorkerFailures.test_a_model_outage_is_retried_then_stored_fail_closed_on_the_last_attempt",
      W + ".WorkerFailures.test_an_unexpected_exception_is_recorded_by_type_only_and_retried_a_bounded_number_of_times", W + ".WorkerFailures.test_a_permanent_model_refusal_is_not_retried",
      W + ".BrokerQueue.test_a_retry_is_published_again_with_its_back_off", W + ".EngineAndRunner.test_a_retry_produces_the_same_payload_hash",
      W + ".WorkerOnRealPostgres.test_retry_after_a_lost_acknowledgement_stores_one_case"]),
    ("R05", "worker interruption and recovery",
     [W + ".Maintenance.test_reaper_requeues_a_job_whose_worker_disappeared", J + ".MemoryJobStoreTests.test_reaper_requeues_a_lost_job_and_fails_it_when_attempts_are_gone",
      W + ".WorkerFailures.test_a_worker_that_lost_its_lease_changes_nothing", W + ".WorkerFailures.test_a_poll_worker_exits_with_75_after_a_timeout",
      W + ".WorkerFailures.test_a_store_outage_while_completing_is_retried_and_stores_one_case", W + ".WorkerFailures.test_if_the_store_is_down_when_failing_the_lease_is_left_to_expire",
      W + ".BrokerQueue.test_a_lost_message_is_republished_after_the_republish_interval", W + ".BrokerQueue.test_a_broker_outage_leaves_the_job_queued_and_the_sweeper_publishes_it_later",
      O + ".HeartbeatAndStop.test_sweeper_and_poll_loops_beat_and_stop_on_request", O + ".HeartbeatAndStop.test_stop_handler_sets_the_event"]),
    ("R06", "database failures",
     [A + ".OutageTests.test_database_down_gives_503_without_internals", J + ".MemoryJobStoreTests.test_a_database_outage_raises_db_error",
      O + ".ResilientDriverTests.test_a_connection_failure_discards_the_connection_and_the_next_call_reconnects", O + ".ResilientDriverTests.test_a_failed_call_is_not_retried",
      W + ".Maintenance.test_maintenance_survives_a_store_outage", W + ".WorkerFailures.test_a_database_refusal_is_final", W + ".WorkerFailures.test_claim_failure_propagates_so_the_broker_redelivers",
      A + ".SubmitTests.test_a_valid_alert_is_accepted_with_a_job_id", H + ".FailureContainment.test_a_database_outage_reaches_the_client_as_503_with_no_connection_details"]),
    ("R07", "invalid model output",
     [W + ".WorkerFailures.test_malformed_replies_end_in_a_fail_closed_case", W + ".ClassifyTests.test_classification_table", W + ".GuardTests.test_a_guard_signal_blocks_auto_close",
      W + ".GuardTests.test_adjust_routing_only_makes_things_more_cautious", H + ".Week4Regression.test_an_unusable_verdict_is_never_auto_closed",
      H + ".Week4Regression.test_the_payload_builder_drops_labels_outside_the_allow_list"]),
    ("R08", "timeout behavior",
     [W + ".WorkerFailures.test_a_timeout_is_recorded_and_the_late_result_is_discarded", W + ".WorkerFailures.test_a_timeout_with_attempts_left_is_retried",
      J + ".MemoryJobStoreTests.test_timeout_on_the_last_attempt_is_timed_out", I + ".SettingsTests.test_lease_must_exceed_the_timeout",
      D + ".ComposeFile.test_the_celery_hard_limit_leaves_room_before_the_stop_grace_period_ends", O + ".CeleryConfigTests.test_reliability_settings"]),
    ("R09", "rate limiting and bounded admission",
     [A + ".LimitTests.test_rate_limit_per_user_with_refill", A + ".LimitTests.test_a_rate_limited_request_is_not_parsed", A + ".LimitTests.test_limiter_memory_is_bounded",
      A + ".LimitTests.test_queue_full_returns_429_and_stores_nothing", A + ".ReadLimitedTests.test_a_declared_length_over_the_limit_is_refused_without_reading",
      A + ".FastApiTests.test_oversize_body_is_413", J + ".MemoryJobStoreTests.test_queue_full_is_refused_and_nothing_is_stored", L + ".InProcessRunTests.test_api_rate_limit_shows_up_as_429s"]),
    ("R10", "audit logging",
     [A + ".RejectionTests.test_audit_record_has_only_code_field_size_and_hash", A + ".RejectionTests.test_a_failure_to_audit_does_not_turn_a_refusal_into_an_acceptance",
      A + ".ApiOnRealPostgres.test_rejections_are_audited_in_the_database_without_content", S + ".FullSuite.test_audit_events_exist_for_every_refusal_and_guard_finding",
      S + ".DefectsTheSuiteFound.test_bad_idempotency_key_is_refused_and_audited_without_the_header_value", W + ".GuardTests.test_a_secret_in_the_reply_is_withheld_and_audited_without_the_secret",
      J + ".MemoryJobStoreTests.test_security_event_types_are_checked", J + ".MemoryJobStoreTests.test_events_are_recorded_in_order", J + ".PgJobStoreTests.test_events_are_append_only",
      H + ".Week4Regression.test_the_audit_chain_verifies_and_detects_tampering"]),
    ("R11", "approval enforcement",
     [A + ".EndToEnd.test_alert_to_job_to_case_to_approval_and_nothing_is_executed", H + ".ApprovalEnforcement.test_roles_at_the_http_boundary",
      H + ".ApprovalEnforcement.test_a_worker_never_creates_anything_but_pending_proposals", H + ".ApprovalEnforcement.test_execution_needs_an_approved_action_and_only_records_a_simulation",
      H + ".ApprovalEnforcement.test_a_decision_is_final_and_replays_are_idempotent", W + ".WorkerBasics.test_the_proposed_actions_are_pending_and_nothing_is_executed"]),
    ("R12", "secret redaction",
     [H + ".SecretRedaction.test_no_secret_reaches_any_output_on_the_happy_path", H + ".SecretRedaction.test_no_secret_reaches_any_output_when_everything_fails",
      H + ".SecretRedaction.test_the_public_settings_view_and_startup_errors_carry_no_secret", W + ".WorkerBasics.test_logs_contain_no_alert_content",
      O + ".StartupTests.test_worker_error_messages_never_contain_the_connection_string", I + ".SettingsTests.test_public_view_has_no_secret_like_key",
      I + ".SettingsTests.test_bad_values_are_listed_without_echoing_them", S + ".FullSuite.test_results_are_json_serialisable_and_contain_no_secret", W + ".GuardTests.test_guard_units",
      D + ".ComposeFile.test_no_credential_is_written_in_the_file", D + ".Dockerfile.test_no_secret_in_env_or_arg", D + ".SupportFiles.test_env_example_holds_only_placeholders",
      O + ".AdminTests.test_weak_password_and_bad_names_are_refused_without_echoing_the_password"]),
    ("R13", "configuration errors",
     [I + ".SettingsTests.test_defaults_are_conservative", I + ".SettingsTests.test_live_model_needs_both_switches", I + ".SettingsTests.test_bad_values_are_listed_without_echoing_them",
      I + ".SettingsTests.test_memory_default_on_needs_a_directory", O + ".StartupTests.test_api_refuses_to_build_without_authentication", O + ".StartupTests.test_api_needs_a_database_url",
      O + ".StartupTests.test_api_refuses_the_memory_backend_and_bad_settings", O + ".StartupTests.test_dev_mode_is_refused_off_loopback",
      O + ".StartupTests.test_a_worker_refuses_to_build_without_a_database_url_or_with_the_memory_backend",
      O + ".CeleryConfigTests.test_a_missing_celery_package_gives_a_clear_error_without_the_url", D + ".ComposeFile.test_every_required_variable_fails_loudly_and_is_documented",
      W + ".EngineAndRunner.test_gemini_provider_refuses_to_exist_without_both_switches"]),
    ("R14", "health-check accuracy",
     [A + ".OutageTests.test_health", A + ".OutageTests.test_readiness_reports_a_down_broker_as_degraded", A + ".OutageTests.test_health_shows_no_job_or_case_data",
      A + ".OutageTests.test_broker_down_still_accepts_and_the_sweeper_catches_up", W + ".BrokerQueue.test_readiness_reports_a_down_broker",
      O + ".HeartbeatAndStop.test_health_check_needs_a_fresh_heartbeat_file", O + ".HeartbeatAndStop.test_health_flag_through_main",
      D + ".ComposeFile.test_every_long_running_service_has_a_health_check_and_dependencies_wait_for_it", D + ".Dockerfile.test_has_a_health_check_and_does_not_install_the_live_model_by_default"]),
    ("R15", "Week 4 behaviour is unchanged (regression)",
     [H + ".Week4Regression.test_policy_decisions_are_pinned", H + ".Week4Regression.test_the_policy_file_is_the_locked_one", H + ".Week4Regression.test_week4_routes_are_exactly_as_locked",
      H + ".Week4Regression.test_an_unusable_verdict_is_never_auto_closed", H + ".Week4Regression.test_the_audit_chain_verifies_and_detects_tampering",
      A + ".EndToEnd.test_week4_routes_are_unchanged", A + ".RouteTableTests.test_week5_names_do_not_shadow_week4_names", W + ".EngineAndRunner.test_the_instrumented_engine_equals_the_week4_offline_driver",
      W + ".EngineAndRunner.test_the_policy_is_the_week4_policy", W + ".EngineAndRunner.test_parse_retry_constant_matches_the_project_value", W + ".EngineAndRunner.test_model_constants_match_week2",
      "test_week5_release.LockChecks.test_the_real_lock_layout_is_verified_and_a_changed_locked_file_is_caught"]),
]

PG_ONLY = ("Postgres", "Pg")


def all_ids():
    return [t for _rid, _name, tests in REQUIREMENTS for t in tests]


def needs_postgres(test_id):
    cls = test_id.split(".")[1]
    return any(m in cls for m in PG_ONLY)

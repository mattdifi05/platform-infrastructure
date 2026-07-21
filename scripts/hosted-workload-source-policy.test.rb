#!/usr/bin/env ruby
# frozen_string_literal: true

require "minitest/autorun"
require_relative "hosted-workload-source-policy"

class HostedWorkloadSourcePolicyTest < Minitest::Test
  def parse(source)
    HostedWorkloadSourcePolicy.parse_compose(source, "fixture")
  end

  def test_accepts_minimal_mapping
    assert_equal ["example-app-web"], parse("services:\n  example-app-web:\n    image: example@test\n").fetch("services").keys
  end

  def test_rejects_duplicate_keys
    error = assert_raises(ArgumentError) { parse("services:\n  app: {}\n  app: {}\n") }
    assert_match(/duplicate key app/, error.message)
  end

  def test_rejects_aliases_and_merge_keys
    assert_raises(ArgumentError) { parse("x: &base {}\nservices:\n  app: *base\n") }
    assert_raises(ArgumentError) { parse("services:\n  app:\n    <<: {}\n") }
  end

  def test_rejects_custom_tags_and_multiple_documents
    assert_raises(ArgumentError) { parse("services: !host {}\n") }
    assert_raises(ArgumentError) { parse("services: {}\n---\nservices: {}\n") }
  end

  def test_rejects_oversized_source
    assert_raises(ArgumentError) { parse("services: {}\n#" + ("x" * HostedWorkloadSourcePolicy::MAX_COMPOSE_BYTES)) }
  end

  def test_rejects_all_compose_interpolation_and_dollar_escapes
    ["$IMAGE", "${IMAGE}", "${IMAGE:-fallback}", "$$IMAGE"].each do |value|
      error = assert_raises(ArgumentError) do
        parse("services:\n  app:\n    image: '#{value}'\n")
      end
      assert_match(/cannot use Compose interpolation or dollar escapes/, error.message)
    end
  end

  def test_rejects_pid_namespace_sharing_and_non_numeric_users
    [{ "pid" => "service:postgres" }, { "pid" => "container:foreign" }, { "user" => "app:app" }, { "user" => "1000" }, { "user" => "0:1000" }].each do |service|
      error = assert_raises(ArgumentError) do
        HostedWorkloadSourcePolicy.validate_source_model({ "services" => { "app" => service } }, "fixture")
      end
      assert_match(/PID namespace|canonical numeric uid:gid/, error.message)
    end
    assert HostedWorkloadSourcePolicy.validate_source_model({ "services" => { "app" => { "user" => "1000:1000" } } }, "fixture")
  end

  def test_rejects_unbounded_or_non_local_logging
    [
      { "driver" => "json-file" },
      { "driver" => "local", "options" => { "max-size" => "1g", "max-file" => "99" } },
      { "driver" => "local" }
    ].each do |logging|
      error = assert_raises(ArgumentError) do
        HostedWorkloadSourcePolicy.validate_source_model({ "services" => { "app" => { "logging" => logging } } }, "fixture")
      end
      assert_match(/must use bounded local logging/, error.message)
    end
  end

  def test_binds_memswap_and_rejects_oom_priority_controls
    error = assert_raises(ArgumentError) do
      HostedWorkloadSourcePolicy.validate_source_model(
        { "services" => { "app" => { "mem_limit" => "256m", "memswap_limit" => "512m" } } }, "fixture"
      )
    end
    assert_match(/bind memswap_limit exactly to mem_limit/, error.message)
    %w[oom_kill_disable oom_score_adj mem_swappiness].each do |field|
      error = assert_raises(ArgumentError) do
        HostedWorkloadSourcePolicy.validate_source_model({ "services" => { "app" => { field => 0 } } }, "fixture")
      end
      assert_match(/cannot override OOM or swappiness controls/, error.message)
    end
  end

  def test_rejects_include_and_extends_before_render
    include_model = parse("include:\n  - other.yaml\nservices:\n  app: {}\n")
    assert_raises(ArgumentError) { HostedWorkloadSourcePolicy.validate_source_model(include_model, "fixture") }
    extends_model = parse("services:\n  app:\n    extends:\n      file: base.yaml\n      service: base\n")
    assert_raises(ArgumentError) { HostedWorkloadSourcePolicy.validate_source_model(extends_model, "fixture") }
  end

  def test_rejects_every_env_file_form_before_compose_can_read_it
    [
      "../../host.env",
      "/etc/credential-bearing.env",
      ["linked.env", "mutable.env"],
      [{ "path" => "workload.env", "required" => false }]
    ].each do |env_file|
      model = { "services" => { "app" => { "env_file" => env_file } } }
      error = assert_raises(ArgumentError) do
        HostedWorkloadSourcePolicy.validate_source_model(model, "fixture")
      end
      assert_match(/cannot use env_file/, error.message)
    end
  end

  def test_rejects_service_volume_inheritance_before_render
    model = parse("services:\n  app:\n    volumes_from:\n      - postgres:rw\n")
    error = assert_raises(ArgumentError) do
      HostedWorkloadSourcePolicy.validate_source_model(model, "fixture")
    end
    assert_match(/cannot use volumes_from/, error.message)
  end

  def test_rejects_every_service_lifecycle_hook_before_render
    %w[post_start pre_start pre_stop].each do |hook|
      model = parse("services:\n  app:\n    #{hook}:\n      - command: id\n")
      error = assert_raises(ArgumentError) do
        HostedWorkloadSourcePolicy.validate_source_model(model, "fixture")
      end
      assert_match(/cannot use lifecycle hooks/, error.message)
    end
  end

  def test_rejects_all_service_scaling_before_resource_admission
    [
      { "scale" => 2 },
      { "deploy" => { "replicas" => 2 } },
      { "deploy" => { "mode" => "global" } }
    ].each do |service|
      error = assert_raises(ArgumentError) do
        HostedWorkloadSourcePolicy.validate_source_model({ "services" => { "app" => service } }, "fixture")
      end
      assert_match(/cannot set (?:scale|deploy\.(?:replicas|mode))/, error.message)
    end
  end

  def test_rejects_file_backed_configs_and_service_config_grants
    file_config = parse("configs:\n  host-data:\n    file: /etc/hosts\nservices:\n  app: {}\n")
    assert_raises(ArgumentError) { HostedWorkloadSourcePolicy.validate_source_model(file_config, "fixture") }
    grant = parse("services:\n  app:\n    configs:\n      - platform-config\n")
    assert_raises(ArgumentError) { HostedWorkloadSourcePolicy.validate_source_model(grant, "fixture") }
  end

  def test_rejects_inline_and_host_environment_configs
    [{ "content" => "hostile" }, { "environment" => "HOST_SECRET" }].each do |definition|
      model = { "configs" => { "example-app_config" => definition }, "services" => { "app" => {} } }
      error = assert_raises(ArgumentError) do
        HostedWorkloadSourcePolicy.validate_source_model(model, "fixture")
      end
      assert_match(/cannot use inline or host-environment content/, error.message)
    end
  end

  def test_rejects_host_device_controls
    [
      "services:\n  app:\n    devices:\n      - /dev/kvm:/dev/kvm\n",
      "services:\n  app:\n    device_cgroup_rules:\n      - c 10:232 rwm\n"
    ].each do |document|
      error = assert_raises(ArgumentError) do
        HostedWorkloadSourcePolicy.validate_source_model(parse(document), "fixture")
      end
      assert_match(/cannot request host device access/, error.message)
    end
  end

  def test_rejects_supplemental_device_groups
    model = parse("services:\n  app:\n    group_add: [video, '44']\n")
    error = assert_raises(ArgumentError) do
      HostedWorkloadSourcePolicy.validate_source_model(model, "fixture")
    end
    assert_match(/cannot add supplemental groups/, error.message)
  end

  def test_rejects_local_volume_driver_options
    model = parse(<<~YAML)
      volumes:
        host-data:
          driver: local
          driver_opts:
            type: none
            o: bind
            device: /srv/platform
      services:
        app:
          volumes:
            - host-data:/data
    YAML
    error = assert_raises(ArgumentError) do
      HostedWorkloadSourcePolicy.validate_source_model(model, "fixture")
    end
    assert_match(/cannot use local driver options/, error.message)
  end

  def test_rejects_external_and_foreign_workload_volume_aliases
    [
      { "external" => true },
      { "name" => "foreign_data" }
    ].each do |definition|
      model = { "volumes" => { "example-app_data" => definition }, "services" => { "example-app-web" => {} } }
      error = assert_raises(ArgumentError) do
        HostedWorkloadSourcePolicy.validate_source_model(model, "fixture", workload_id: "example-app", project_name: "fixture")
      end
      assert_match(/cannot alias an external or foreign physical volume/, error.message)
    end
    model = { "volumes" => { "other_data" => {} }, "services" => { "example-app-web" => {} } }
    assert_raises(ArgumentError) do
      HostedWorkloadSourcePolicy.validate_source_model(model, "fixture", workload_id: "example-app", project_name: "fixture")
    end
    ["attacker_example-app_data", ["attacker_example-app_data"]].each do |definition|
      model = { "volumes" => { "example-app_data" => definition }, "services" => { "example-app-web" => {} } }
      error = assert_raises(ArgumentError) do
        HostedWorkloadSourcePolicy.validate_source_model(model, "fixture", workload_id: "example-app", project_name: "fixture")
      end
      assert_match(/must be null or a mapping/, error.message)
    end
  end

  def test_binds_external_secrets_to_workload_owned_physical_names
    valid = {
      "secrets" => { "example-app-api-key" => { "external" => true, "name" => "fixture_example-app-api-key" } },
      "services" => { "example-app-web" => { "secrets" => ["example-app-api-key"] } }
    }
    assert HostedWorkloadSourcePolicy.validate_source_model(
      valid, "fixture", workload_id: "example-app", project_name: "fixture", declared_secrets: ["example-app-api-key"]
    )
    [{ "external" => true }, { "external" => true, "name" => "foreign_key" }, { "file" => "/tmp/key" }].each do |definition|
      model = { "secrets" => { "example-app-api-key" => definition }, "services" => { "example-app-web" => {} } }
      error = assert_raises(ArgumentError) do
        HostedWorkloadSourcePolicy.validate_source_model(
          model, "fixture", workload_id: "example-app", project_name: "fixture", declared_secrets: ["example-app-api-key"]
        )
      end
      assert_match(/must bind workload-owned external secret/, error.message)
    end
  end

  def test_rejects_compose_api_socket
    model = parse("services:\n  app:\n    use_api_socket: true\n")
    error = assert_raises(ArgumentError) do
      HostedWorkloadSourcePolicy.validate_source_model(model, "fixture")
    end
    assert_match(/cannot use the Compose API socket/, error.message)
  end

  def test_rejects_external_service_providers
    model = parse(<<~YAML)
      services:
        app:
          provider:
            type: hostile-provider
            options:
              command: /host/tool
    YAML
    error = assert_raises(ArgumentError) do
      HostedWorkloadSourcePolicy.validate_source_model(model, "fixture")
    end
    assert_match(/cannot delegate execution to a provider/, error.message)
  end

  def test_rejects_oci_runtime_overrides
    model = parse("services:\n  app:\n    runtime: kata-runtime\n")
    error = assert_raises(ArgumentError) do
      HostedWorkloadSourcePolicy.validate_source_model(model, "fixture")
    end
    assert_match(/cannot override the OCI runtime/, error.message)
  end

  def test_rejects_stop_grace_period_overrides
    model = parse("services:\n  app:\n    stop_grace_period: 24h\n")
    error = assert_raises(ArgumentError) do
      HostedWorkloadSourcePolicy.validate_source_model(model, "fixture")
    end
    assert_match(/cannot override the stop grace period/, error.message)
  end

  def test_rejects_gpu_and_accelerator_requests
    [
      "services:\n  app:\n    gpus: all\n",
      "services:\n  app:\n    device_requests:\n      - capabilities: [gpu]\n",
      "services:\n  app:\n    deploy:\n      resources:\n        reservations:\n          devices:\n            - driver: nvidia\n              capabilities: [gpu]\n"
    ].each do |document|
      error = assert_raises(ArgumentError) do
        HostedWorkloadSourcePolicy.validate_source_model(parse(document), "fixture")
      end
      assert_match(/cannot request GPU or accelerator access/, error.message)
    end
  end
end

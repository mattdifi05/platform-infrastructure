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

  def test_rejects_nested_workload_ids_independent_of_order_and_depth
    [
      %w[billing billing-api],
      %w[billing-api billing],
      %w[billing-api-admin billing billing-api]
    ].each do |ids|
      workloads = ids.map { |id| { "id" => id } }
      error = assert_raises(ArgumentError) do
        HostedWorkloadSourcePolicy.validate_workload_id_set!(workloads)
      end
      assert_match(/Prefix-colliding workload ids/, error.message)
    end
  end

  def test_preserves_non_colliding_and_single_owner_textual_prefixes
    assert_equal %w[billing billingapi],
                 HostedWorkloadSourcePolicy.validate_workload_id_set!([
                   { "id" => "billing" },
                   { "id" => "billingapi" }
                 ])
    assert HostedWorkloadSourcePolicy.validate_source_model(
      {
        "secrets" => {
          "billing-api-key" => {
            "external" => true,
            "name" => "fixture_billing-api-key"
          }
        },
        "services" => {
          "billing-api-web" => {
            "secrets" => ["billing-api-key"],
            "security_opt" => ["no-new-privileges:true"]
          }
        }
      },
      "fixture",
      workload_id: "billing",
      project_name: "fixture",
      declared_secrets: ["billing-api-key"]
    )
  end

  def test_rejects_noncanonical_workload_ids_without_normalization
    ["b", "Billing", " billing ", "1billing", "billing_api", "billing.api", "b#{"a" * 63}"].each do |id|
      error = assert_raises(ArgumentError) do
        HostedWorkloadSourcePolicy.validate_workload_id_set!([{ "id" => id }])
      end
      assert_match(/canonical workload id/i, error.message)
    end
    assert_equal ["ab"], HostedWorkloadSourcePolicy.validate_workload_id_set!([{ "id" => "ab" }])
    assert_equal ["billing-api"],
                 HostedWorkloadSourcePolicy.validate_workload_id_set!([{ "id" => "billing-api" }])
    maximum_id = "b#{"a" * 60}"
    assert_equal [maximum_id],
                 HostedWorkloadSourcePolicy.validate_workload_id_set!([{ "id" => maximum_id }])
    [62, 63, 64].each do |length|
      oversized_id = "b#{"a" * (length - 1)}"
      error = assert_raises(ArgumentError) do
        HostedWorkloadSourcePolicy.validate_workload_id_set!([{ "id" => oversized_id }])
      end
      assert_match(/canonical workload id/i, error.message)
    end
  end

  def test_rejects_a_sole_claimant_stealing_another_exact_workload_secret
    model = secret_model(
      secret_names: ["billingapi-api-key"],
      grants: [{ "source" => "billingapi-api-key", "target" => "billingapi-api-key" }],
      file_target: "billingapi-api-key"
    )
    error = assert_raises(ArgumentError) do
      HostedWorkloadSourcePolicy.validate_source_model(
        model,
        "fixture",
        workload_id: "billing",
        workload_ids: %w[billing billingapi],
        project_name: "fixture",
        declared_secrets: ["billingapi-api-key"]
      )
    end
    assert_match(/canonical secret owner|belongs to workload billingapi/i, error.message)
  end

  def test_rejects_secret_file_without_an_exact_grant
    ungranted = secret_model(
      secret_names: ["billing-api-key"],
      grants: [{ "source" => "billing-api-key", "target" => "billing-api-key" }],
      file_target: "ungranted-secret"
    )
    error = assert_raises(ArgumentError) do
      HostedWorkloadSourcePolicy.validate_source_model(
        ungranted,
        "fixture",
        workload_id: "billing",
        project_name: "fixture",
        declared_secrets: ["billing-api-key"]
      )
    end
    assert_match(/secret file.*grant|ungranted secret target/i, error.message)
  end

  def test_rejects_duplicate_secret_grant_targets
    duplicate = secret_model(
      secret_names: %w[billing-api-key billing-signing-key],
      grants: [
        { "source" => "billing-api-key", "target" => "billing-token" },
        { "source" => "billing-signing-key", "target" => "billing-token" }
      ],
      file_target: "billing-token"
    )
    error = assert_raises(ArgumentError) do
      HostedWorkloadSourcePolicy.validate_source_model(
        duplicate,
        "fixture",
        workload_id: "billing",
        project_name: "fixture",
        declared_secrets: %w[billing-api-key billing-signing-key]
      )
    end
    assert_match(/duplicate secret grant target|secret target.*duplicate/i, error.message)
  end

  def test_preserves_short_long_alias_and_long_default_secret_grants
    [
      ["billing-api-key", "billing-api-key"],
      [{ "source" => "billing-api-key", "target" => "billing-token" }, "billing-token"],
      [{ "source" => "billing-api-key" }, "billing-api-key"]
    ].each do |grant, file_target|
      assert HostedWorkloadSourcePolicy.validate_source_model(
        secret_model(secret_names: ["billing-api-key"], grants: [grant], file_target: file_target),
        "fixture",
        workload_id: "billing",
        project_name: "fixture",
        declared_secrets: ["billing-api-key"]
      )
    end
  end

  def test_rejects_aliases_and_merge_keys
    assert_raises(ArgumentError) { parse("x: &base {}\nservices:\n  app: *base\n") }
    assert_raises(ArgumentError) { parse("services:\n  app:\n    <<: {}\n") }
  end

  def secret_model(secret_names:, grants:, file_target:)
    {
      "secrets" => secret_names.to_h do |name|
        [name, { "external" => true, "name" => "fixture_#{name}" }]
      end,
      "services" => {
        "billing-web" => {
          "environment" => { "BILLING_TOKEN_FILE" => "/run/secrets/#{file_target}" },
          "secrets" => grants,
          "security_opt" => ["no-new-privileges:true"]
        }
      }
    }
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

  def test_requires_exact_no_new_privileges_security_option
    [
      ["no-new-privileges:true", "seccomp=unconfined"],
      ["no-new-privileges:true", "apparmor=unconfined"],
      ["seccomp=unconfined"]
    ].each do |security_opt|
      error = assert_raises(ArgumentError) do
        HostedWorkloadSourcePolicy.validate_source_model(
          { "services" => { "example-app-web" => { "security_opt" => security_opt } } },
          "fixture",
          workload_id: "example-app",
          project_name: "fixture"
        )
      end
      assert_match(/security_opt must be exactly/, error.message)
    end
    assert HostedWorkloadSourcePolicy.validate_source_model(
      { "services" => { "example-app-web" => { "security_opt" => ["no-new-privileges:true"] } } },
      "fixture",
      workload_id: "example-app",
      project_name: "fixture"
    )
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

  def test_named_volumes_cannot_shadow_protected_targets_or_use_nested_controls
    [
      { "type" => "volume", "source" => "example-app_data", "target" => "/var/run/docker.sock" },
      { "type" => "volume", "source" => "example-app_data", "target" => "/run/platform/hosted-workloads.lock.json" },
      { "type" => "volume", "source" => "example-app_data", "target" => "/data", "read_only" => false },
      { "type" => "volume", "source" => "example-app_data", "target" => "/data", "volume" => { "nocopy" => false, "subpath" => "host" } }
    ].each do |mount|
      error = assert_raises(ArgumentError) do
        HostedWorkloadSourcePolicy.validate_source_model(
          {
            "volumes" => { "example-app_data" => {} },
            "services" => {
              "example-app-web" => {
                "security_opt" => ["no-new-privileges:true"],
                "volumes" => [mount]
              }
            }
          },
          "fixture",
          workload_id: "example-app",
          project_name: "fixture"
        )
      end
      assert_match(/exact long-syntax mounts targeting only \/data/, error.message)
    end
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
      assert_match(/cannot (?:set (?:scale|deploy\.(?:replicas|mode))|define deploy controls)/, error.message)
    end
  end

  def test_rejects_file_backed_configs_and_service_config_grants
    file_config = parse("configs:\n  host-data:\n    file: /etc/hosts\nservices:\n  app: {}\n")
    assert_raises(ArgumentError) { HostedWorkloadSourcePolicy.validate_source_model(file_config, "fixture") }
    grant = parse("services:\n  app:\n    configs:\n      - platform-config\n")
    assert_raises(ArgumentError) { HostedWorkloadSourcePolicy.validate_source_model(grant, "fixture") }
  end

  def test_rejects_any_workload_top_level_config_alias
    model = {
      "configs" => { "attacker_trust_key" => { "external" => true } },
      "services" => { "example-app-web" => {} }
    }
    error = assert_raises(ArgumentError) do
      HostedWorkloadSourcePolicy.validate_source_model(
        model,
        "fixture",
        workload_id: "example-app",
        project_name: "fixture",
        declared_secrets: []
      )
    end
    assert_match(/cannot define, alias, or replace top-level configs/, error.message)
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

  def test_binds_network_identity_and_rejects_attachment_aliases
    [
      { "external" => true },
      { "name" => "platform_docker_control" }
    ].each do |definition|
      model = { "networks" => { "example_app_ingress" => definition }, "services" => { "example-app-web" => {} } }
      error = assert_raises(ArgumentError) do
        HostedWorkloadSourcePolicy.validate_source_model(model, "fixture", workload_id: "example-app", project_name: "fixture")
      end
      assert_match(/cannot alias an external or foreign physical network/, error.message)
    end
    aliased = {
      "networks" => { "example_app_ingress" => { "internal" => true } },
      "services" => { "example-app-web" => { "networks" => { "example_app_ingress" => { "aliases" => ["postgres"] } } } }
    }
    error = assert_raises(ArgumentError) do
      HostedWorkloadSourcePolicy.validate_source_model(aliased, "fixture", workload_id: "example-app", project_name: "fixture")
    end
    assert_match(/cannot set network aliases or address overrides/, error.message)
    [nil, "attacker_example_app_ingress", ["example_app_ingress"], true, 7].each do |definition|
      malformed = { "networks" => { "example_app_ingress" => definition }, "services" => { "example-app-web" => {} } }
      error = assert_raises(ArgumentError) do
        HostedWorkloadSourcePolicy.validate_source_model(malformed, "fixture", workload_id: "example-app", project_name: "fixture")
      end
      assert_match(/must be a mapping/, error.message)
    end
    collision = {
      "networks" => { "example_app_shadow_ingress" => {} },
      "services" => { "example-app-web" => { "networks" => ["example_app_shadow_ingress"] } }
    }
    error = assert_raises(ArgumentError) do
      HostedWorkloadSourcePolicy.validate_source_model(collision, "fixture", workload_id: "example-app", project_name: "fixture")
    end
    assert_match(/not an exact workload-owned network/, error.message)
  end

  def test_binds_exact_network_topology_per_zone
    assert HostedWorkloadSourcePolicy.validate_source_model(
      {
        "networks" => {
          "example_app_ingress" => { "internal" => true },
          "example_app_egress" => { "internal" => false }
        },
        "services" => {
          "example-app-web" => {
            "networks" => ["example_app_ingress", "example_app_egress"],
            "security_opt" => ["no-new-privileges:true"]
          }
        }
      },
      "fixture",
      workload_id: "example-app",
      project_name: "fixture"
    )
    [
      { "internal" => false },
      { "internal" => true, "driver" => "bridge" },
      { "internal" => true, "driver_opts" => { "com.docker.network.bridge.name" => "host0" } },
      { "internal" => true, "ipam" => { "config" => [{ "subnet" => "172.30.0.0/16" }] } },
      { "internal" => true, "attachable" => true },
      { "internal" => true, "labels" => { "com.docker.compose.network" => "platform_docker_control" } },
      { "internal" => true, "enable_ipv4" => false },
      { "internal" => true, "enable_ipv6" => true }
    ].each do |definition|
      model = { "networks" => { "example_app_ingress" => definition }, "services" => { "example-app-web" => {} } }
      error = assert_raises(ArgumentError) do
        HostedWorkloadSourcePolicy.validate_source_model(model, "fixture", workload_id: "example-app", project_name: "fixture")
      end
      assert_match(/must declare only internal: true/, error.message)
    end
    model = { "networks" => { "example_app_egress" => { "internal" => true } }, "services" => { "example-app-web" => {} } }
    error = assert_raises(ArgumentError) do
      HostedWorkloadSourcePolicy.validate_source_model(model, "fixture", workload_id: "example-app", project_name: "fixture")
    end
    assert_match(/must declare only internal: false/, error.message)
  end

  def test_rejects_workload_network_collision_with_protected_core_name
    model = {
      "networks" => { "platform_postgres" => { "internal" => true } },
      "services" => { "platform-web" => { "networks" => ["platform_postgres"] } }
    }
    error = assert_raises(ArgumentError) do
      HostedWorkloadSourcePolicy.validate_source_model(
        model,
        "fixture",
        workload_id: "platform",
        project_name: "fixture",
        protected_networks: ["platform_postgres"]
      )
    end
    assert_match(/collides with a protected core network/, error.message)
  end

  def test_rejects_host_device_controls
    [
      "services:\n  app:\n    devices:\n      - /dev/kvm:/dev/kvm\n",
      "services:\n  app:\n    device_cgroup_rules:\n      - c 10:232 rwm\n",
      "services:\n  app:\n    blkio_config:\n      weight: 300\n      device_read_bps:\n        - path: /dev/sda\n          rate: 1mb\n"
    ].each do |document|
      error = assert_raises(ArgumentError) do
        HostedWorkloadSourcePolicy.validate_source_model(parse(document), "fixture")
      end
      assert_match(/cannot request host device access|bounded global weight/, error.message)
    end
  end

  def test_rejects_label_files_ambient_environment_and_deploy_controls
    [
      ["services:\n  app:\n    label_file: /tmp/attacker.labels\n", /cannot load labels from a host file/],
      ["services:\n  app:\n    environment:\n      DATABASE_URL:\n", /explicit mapping with no ambient null values/],
      ["services:\n  app:\n    environment:\n      - DATABASE_URL\n", /explicit mapping with no ambient null values/],
      ["services:\n  app:\n    deploy:\n      resources:\n        limits:\n          cpus: '64'\n          memory: 64G\n          pids: 999999\n", /cannot define deploy controls/]
    ].each do |document, message|
      error = assert_raises(ArgumentError) do
        HostedWorkloadSourcePolicy.validate_source_model(parse(document), "fixture")
      end
      assert_match(message, error.message)
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
      assert_match(/implicit Docker local driver/, error.message)
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

  def test_rejects_protected_core_resource_collisions_and_unused_resources
    volume_collision = {
      "volumes" => { "enterprise_local_registry_data" => {} },
      "services" => {
        "enterprise-web" => {
          "security_opt" => ["no-new-privileges:true"],
          "volumes" => [
            { "type" => "volume", "source" => "enterprise_local_registry_data", "target" => "/data" }
          ]
        }
      }
    }
    error = assert_raises(ArgumentError) do
      HostedWorkloadSourcePolicy.validate_source_model(
        volume_collision,
        "fixture",
        workload_id: "enterprise",
        project_name: "fixture",
        protected_resources: {
          "configs" => [],
          "networks" => [],
          "secrets" => [],
          "services" => [],
          "volumes" => ["enterprise_local_registry_data"]
        }
      )
    end
    assert_match(/collides with a protected core volume/, error.message)

    secret_collision = {
      "secrets" => {
        "enterprise-api-key" => {
          "external" => true,
          "name" => "fixture_enterprise-api-key"
        }
      },
      "services" => {
        "enterprise-web" => {
          "security_opt" => ["no-new-privileges:true"],
          "secrets" => ["enterprise-api-key"]
        }
      }
    }
    error = assert_raises(ArgumentError) do
      HostedWorkloadSourcePolicy.validate_source_model(
        secret_collision,
        "fixture",
        workload_id: "enterprise",
        project_name: "fixture",
        declared_secrets: ["enterprise-api-key"],
        protected_resources: {
          "configs" => [],
          "networks" => [],
          "secrets" => ["enterprise-api-key"],
          "services" => [],
          "volumes" => []
        }
      )
    end
    assert_match(/collides with a protected core secret/, error.message)

    unused_network = {
      "networks" => { "enterprise_egress" => { "internal" => false } },
      "services" => {
        "enterprise-web" => {
          "security_opt" => ["no-new-privileges:true"]
        }
      }
    }
    error = assert_raises(ArgumentError) do
      HostedWorkloadSourcePolicy.validate_source_model(
        unused_network,
        "fixture",
        workload_id: "enterprise",
        project_name: "fixture"
      )
    end
    assert_match(/networks must be exactly declared and referenced/, error.message)
  end

  def test_binds_external_secrets_to_workload_owned_physical_names
    valid = {
      "secrets" => { "example-app-api-key" => { "external" => true, "name" => "fixture_example-app-api-key" } },
      "services" => {
        "example-app-web" => {
          "secrets" => ["example-app-api-key"],
          "security_opt" => ["no-new-privileges:true"]
        }
      }
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

  def test_rejects_predeclared_runtime_identity_labels
    [
      { "com.platform.runtime.candidate-id" => "a" * 64 },
      ["com.platform.runtime.commit=#{'b' * 40}"]
    ].each do |labels|
      model = { "services" => { "example-app-web" => { "labels" => labels } } }
      error = assert_raises(ArgumentError) do
        HostedWorkloadSourcePolicy.validate_source_model(model, "fixture", workload_id: "example-app", project_name: "fixture")
      end
      assert_match(/cannot predeclare trusted runtime identity labels/, error.message)
    end
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
      "services:\n  app:\n    deploy:\n      resources:\n        reservations:\n          devices:\n            - driver: nvidia\n              capabilities: [gpu]\n",
      "services:\n  app:\n    deploy:\n      resources:\n        reservations:\n          generic_resources:\n            - discrete_resource_spec:\n                kind: GPU\n                value: 1\n"
    ].each do |document|
      error = assert_raises(ArgumentError) do
        HostedWorkloadSourcePolicy.validate_source_model(parse(document), "fixture")
      end
      assert_match(/cannot request GPU or accelerator access/, error.message)
    end
  end
end

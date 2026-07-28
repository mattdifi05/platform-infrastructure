#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "json"
require "optparse"
require "psych"

module HostedWorkloadSourcePolicy
  VERSION = "hosted-raw-v3"
  CONTROLS = %w[bind-bounded-dependencies bind-bounded-local-logging bind-closed-service-schema bind-exact-healthcheck bind-exact-security-opt bind-exact-ulimits bind-exact-volume-mounts bind-firewall-gated-restart bind-network-identity bind-network-topology bind-no-swap-oom-policy bind-owned-secret-aliases bind-owned-volume-driver bind-owned-volumes bind-platform-extension-records bind-private-pid-numeric-user deny-accelerator-environment deny-api-socket deny-compose-interpolation deny-deploy-controls deny-device-access deny-env-file deny-extends deny-file-configs deny-generic-resources deny-gpu-access deny-include deny-inline-configs deny-label-file deny-lifecycle-hooks deny-local-volume-options deny-providers deny-runtime-identity-labels deny-runtime-overrides deny-scaling deny-stop-grace-overrides deny-supplemental-groups deny-volumes-from].freeze
  MAX_COMPOSE_BYTES = 1_048_576
  STANDARD_TAG_PREFIX = "tag:yaml.org,2002:"
  SERVICE_NAME = /\A[a-z][a-z0-9-]{1,62}\z/
  WORKLOAD_ID = /\A[a-z][a-z0-9-]{1,60}\z/
  WORKLOAD_NETWORK_ZONES = %w[ingress postgres cache bus identity storage observability egress].freeze
  WORKLOAD_SERVICE_KEYS = %w[
    image command entrypoint working_dir environment volumes secrets networks healthcheck
    read_only init restart security_opt cap_drop cap_add user logging pids_limit cpu_shares
    blkio_config ulimits cpus mem_limit memswap_limit mem_reservation labels depends_on
  ].freeze
  PLATFORM_DEPENDENCIES = %w[postgres redis nats minio keycloak alertmanager].freeze
  PLATFORM_NETWORK_EXTENSION_ZONES = {
    "project-router" => %w[ingress],
    "postgres" => %w[postgres],
    "redis" => %w[cache],
    "nats" => %w[bus],
    "keycloak" => %w[identity],
    "minio" => %w[storage],
    "prometheus" => %w[observability]
  }.freeze
  ACCELERATOR_ENVIRONMENT_NAMES = %w[
    CUDA_VISIBLE_DEVICES HIP_VISIBLE_DEVICES ONEAPI_DEVICE_SELECTOR
    ROCR_VISIBLE_DEVICES SYCL_DEVICE_FILTER ZE_AFFINITY_MASK
  ].freeze

  module_function

  def fail!(message)
    raise ArgumentError, message
  end

  def stable(value)
    case value
    when Hash
      value.keys.map(&:to_s).sort.to_h do |key|
        item = value.key?(key) ? value[key] : value[key.to_sym]
        [key, stable(item)]
      end
    when Array
      value.map { |item| stable(item) }
    else
      value
    end
  end

  def validate_workload_id_set!(workloads)
    fail!("Hosted workload lock workloads must be an array.") unless workloads.is_a?(Array)
    ids = workloads.map do |workload|
      id = workload.is_a?(Hash) ? workload["id"] : nil
      fail!("Hosted workload lock contains a noncanonical workload id.") unless id.is_a?(String) && WORKLOAD_ID.match?(id)
      id
    end
    fail!("Hosted workload ids must be unique.") unless ids.uniq.length == ids.length
    ids.sort.combination(2) do |left, right|
      if left.start_with?("#{right}-") || right.start_with?("#{left}-")
        fail!("Prefix-colliding workload ids #{left} and #{right} are forbidden.")
      end
    end
    ids
  end

  def add_canonical_owner!(owners, resource_type, logical_name, workload_id)
    name = logical_name.to_s
    owner = workload_id.to_s
    fail!("#{resource_type} has an invalid canonical owner record.") if name.empty? || owner.empty?
    prior = owners[name]
    if prior && prior != owner
      fail!("#{resource_type} #{name} is ambiguously owned by #{prior} and #{owner}.")
    end
    owners[name] = owner
  end

  def canonical_hyphen_owner!(logical_name, workload_ids, resource_type)
    name = logical_name.to_s
    owners = workload_ids.select { |workload_id| name.start_with?("#{workload_id}-") }
    fail!("#{resource_type} #{name} must have exactly one canonical owner.") unless owners.length == 1
    owners.fetch(0)
  end

  def canonical_volume_owner!(logical_name, workload_ids)
    name = logical_name.to_s
    owners = workload_ids.select { |workload_id| name.start_with?("#{workload_id}_") }
    fail!("Workload volume #{name} must have exactly one canonical owner.") unless owners.length == 1
    owners.fetch(0)
  end

  def canonical_network_owner!(logical_name, workload_ids)
    name = logical_name.to_s
    owners = workload_ids.select do |workload_id|
      WORKLOAD_NETWORK_ZONES.any? { |zone| name == "#{workload_id.tr('-', '_')}_#{zone}" }
    end
    fail!("Workload network #{name} must have exactly one canonical owner.") unless owners.length == 1
    owners.fetch(0)
  end

  def inspect_ast(node, location = "document")
    if node.respond_to?(:tag)
      tag = node.tag.to_s
      if !tag.empty? && !tag.start_with?(STANDARD_TAG_PREFIX)
        fail!("#{location} uses unsupported YAML tag #{tag}.")
      end
    end
    case node
    when Psych::Nodes::Alias
      fail!("#{location} cannot use YAML aliases.")
    when Psych::Nodes::Mapping
      seen = {}
      node.children.each_slice(2).with_index do |(key, value), index|
        fail!("#{location} must use scalar mapping keys.") unless key.is_a?(Psych::Nodes::Scalar)
        name = key.value.to_s
        fail!("#{location} cannot use YAML merge keys.") if name == "<<"
        fail!("#{location} contains duplicate key #{name}.") if seen[name]
        seen[name] = true
        inspect_ast(key, "#{location}.key[#{index}]")
        inspect_ast(value, "#{location}.#{name}")
      end
    when Psych::Nodes::Sequence
      node.children.each_with_index { |child, index| inspect_ast(child, "#{location}[#{index}]") }
    when Psych::Nodes::Scalar
      nil
    else
      node.children.each { |child| inspect_ast(child, location) } if node.respond_to?(:children)
    end
  end

  def parse_compose(bytes, label)
    fail!("#{label} exceeds #{MAX_COMPOSE_BYTES} bytes.") if bytes.bytesize > MAX_COMPOSE_BYTES
    fail!("#{label} cannot use Compose interpolation or dollar escapes.") if bytes.include?("$")
    stream = Psych.parse_stream(bytes, filename: label)
    fail!("#{label} must contain exactly one YAML document.") unless stream.children.length == 1
    document = stream.children.first
    inspect_ast(document, label)
    model = Psych.safe_load(bytes, permitted_classes: [], permitted_symbols: [], aliases: false, filename: label)
    fail!("#{label} must contain a mapping.") unless model.is_a?(Hash)
    services = model["services"]
    fail!("#{label} must contain a services mapping.") unless services.is_a?(Hash)
    model
  rescue Psych::Exception => e
    fail!("#{label} is not safe YAML: #{e.message}")
  end

  def validate_source_model(
    model,
    label,
    workload_id: nil,
    workload_ids: nil,
    project_name: nil,
    declared_secrets: [],
    protected_networks: [],
    protected_resources: {}
  )
    all_workload_ids = if workload_id
                         Array(workload_ids || [workload_id]).map(&:to_s)
                       else
                         []
                       end
    unless workload_id.nil?
      validate_workload_id_set!(all_workload_ids.map { |id| { "id" => id } })
      fail!("#{label} workload id is absent from the canonical workload set.") unless all_workload_ids.include?(workload_id.to_s)
    end
    protected_configs = Array(protected_resources["configs"])
    protected_secrets = Array(protected_resources["secrets"])
    protected_services = Array(protected_resources["services"])
    protected_volumes = Array(protected_resources["volumes"])
    fail!("#{label} cannot use top-level include.") if model.key?("include")
    configs = model["configs"]
    fail!("#{label} configs must be a mapping.") if !configs.nil? && !configs.is_a?(Hash)
    if workload_id && !configs.nil? && !configs.empty?
      fail!("#{label} cannot define, alias, or replace top-level configs.")
    end
    (configs || {}).each do |name, definition|
      fail!("#{label} config #{name} collides with a protected core config.") if workload_id && protected_configs.include?(name)
      fail!("#{label} config #{name} cannot use a file source.") if definition.is_a?(Hash) && definition.key?("file")
      if definition.is_a?(Hash) && (definition.key?("content") || definition.key?("environment"))
        fail!("#{label} config #{name} cannot use inline or host-environment content.")
      end
    end
    secrets = model["secrets"]
    fail!("#{label} secrets must be a mapping.") if !secrets.nil? && !secrets.is_a?(Hash)
    (secrets || {}).each do |name, definition|
      next unless workload_id
      canonical_owner = canonical_hyphen_owner!(name, all_workload_ids, "Workload secret")
      unless canonical_owner == workload_id
        fail!("#{label} secret #{name} belongs to workload #{canonical_owner}, not #{workload_id}.")
      end
      fail!("#{label} secret #{name} collides with a protected core secret.") if protected_secrets.include?(name)
      fail!("#{label} secret #{name} is not declared by the workload manifest.") unless declared_secrets.include?(name)
      expected_name = "#{project_name}_#{name}"
      unless definition.is_a?(Hash) && definition == { "external" => true, "name" => expected_name }
        fail!("#{label} secret #{name} must bind workload-owned external secret #{expected_name}.")
      end
    end
    volumes = model["volumes"]
    fail!("#{label} volumes must be a mapping.") if !volumes.nil? && !volumes.is_a?(Hash)
    (volumes || {}).each do |name, definition|
      fail!("#{label} volume #{name} must be null or a mapping.") unless definition.nil? || definition.is_a?(Hash)
      if workload_id
        canonical_owner = canonical_volume_owner!(name, all_workload_ids)
        unless canonical_owner == workload_id
          fail!("#{label} volume #{name} belongs to workload #{canonical_owner}, not #{workload_id}.")
        end
        fail!("#{label} volume #{name} collides with a protected core volume.") if protected_volumes.include?(name)
        fail!("#{label} volume #{name} is not workload-prefixed.") unless name.start_with?("#{workload_id}_")
        unless definition.nil? || definition.empty?
          fail!("#{label} volume #{name} must use the implicit Docker local driver with no plugin, alias, external binding, or driver options.")
        end
      elsif definition.is_a?(Hash) && definition.key?("driver_opts")
        fail!("#{label} volume #{name} cannot use local driver options.")
      end
    end
    networks = model["networks"]
    fail!("#{label} networks must be a mapping.") if !networks.nil? && !networks.is_a?(Hash)
    workload_network_prefix = "#{workload_id&.tr('-', '_')}_"
    (networks || {}).each do |name, definition|
      fail!("#{label} network #{name} must be a mapping.") unless definition.is_a?(Hash)
      next unless workload_id
      zone = name.to_s.delete_prefix(workload_network_prefix)
      unless name.is_a?(String) && name.start_with?(workload_network_prefix) && WORKLOAD_NETWORK_ZONES.include?(zone)
        fail!("#{label} network #{name} is not an exact workload-owned network.")
      end
      canonical_owner = canonical_network_owner!(name, all_workload_ids)
      unless canonical_owner == workload_id
        fail!("#{label} network #{name} belongs to workload #{canonical_owner}, not #{workload_id}.")
      end
      fail!("#{label} network #{name} collides with a protected core network.") if protected_networks.include?(name)
      if definition.is_a?(Hash) && (definition.key?("external") || definition.key?("name"))
        fail!("#{label} network #{name} cannot alias an external or foreign physical network.")
      end
      expected_internal = zone != "egress"
      unless definition == { "internal" => expected_internal }
        fail!("#{label} network #{name} must declare only internal: #{expected_internal} for its #{zone} zone.")
      end
    end
    model.fetch("services").each do |name, service|
      fail!("#{label} service #{name} must be a mapping.") unless service.is_a?(Hash)
      if workload_id && protected_services.include?(name) && !PLATFORM_NETWORK_EXTENSION_ZONES.key?(name)
        fail!("#{label} service #{name} collides with a protected core service.")
      end
      workload_service = workload_id && !PLATFORM_NETWORK_EXTENSION_ZONES.key?(name)
      if workload_service
        canonical_owner = canonical_hyphen_owner!(name, all_workload_ids, "Workload service")
        unless canonical_owner == workload_id
          fail!("#{label} service #{name} belongs to workload #{canonical_owner}, not #{workload_id}.")
        end
      end
      secret_targets = {}
      if workload_service
        grants = service.fetch("secrets", [])
        fail!("#{label} service #{name} secrets must be a sequence.") unless grants.is_a?(Array)
        grants.each do |entry|
          if entry.is_a?(String)
            source = entry
            target = entry
          elsif entry.is_a?(Hash) && [ ["source"], %w[source target] ].include?(entry.keys.map(&:to_s).sort)
            source = entry["source"]
            target = entry.key?("target") ? entry["target"] : source
          else
            fail!("#{label} service #{name} secret grants must use exact short syntax or exact source/target long syntax.")
          end
          unless source.is_a?(String) && source.match?(SERVICE_NAME) && target.is_a?(String) && target.match?(SERVICE_NAME)
            fail!("#{label} service #{name} secret grants require canonical source and target names.")
          end
          fail!("#{label} service #{name} uses undeclared secret #{source}.") unless declared_secrets.include?(source)
          canonical_owner = canonical_hyphen_owner!(source, all_workload_ids, "Workload secret")
          unless canonical_owner == workload_id
            fail!("#{label} service #{name} secret #{source} belongs to workload #{canonical_owner}, not #{workload_id}.")
          end
          if protected_secrets.include?(source)
            fail!("#{label} service #{name} secret #{source} collides with a protected core secret.")
          end
          if secret_targets.key?(target)
            fail!("#{label} service #{name} has duplicate secret grant target #{target}.")
          end
          secret_targets[target] = source
        end
      end
      labels = service["labels"]
      label_names = case labels
                    when nil then []
                    when Hash then labels.keys.map(&:to_s)
                    when Array then labels.map { |entry| entry.to_s.split("=", 2).first }
                    else
                      fail!("#{label} service #{name} labels must be a mapping or sequence.")
                    end
      if label_names.any? { |label_name| label_name.start_with?("com.platform.runtime.") }
        fail!("#{label} service #{name} cannot predeclare trusted runtime identity labels.")
      end
      if workload_id && service.key?("restart") && service["restart"] != "no"
        fail!("#{label} service #{name} must use restart: no so firewall-gated activation cannot be bypassed after daemon or host restart.")
      end
      fail!("#{label} service #{name} cannot load labels from a host file.") if service.key?("label_file")
      if service.key?("environment")
        environment = service["environment"]
        unless environment.is_a?(Hash) && environment.values.none?(&:nil?)
          fail!("#{label} service #{name} environment must be an explicit mapping with no ambient null values.")
        end
        accelerator_environment = environment.keys.map(&:to_s).select do |key|
          key.start_with?("NVIDIA_") || ACCELERATOR_ENVIRONMENT_NAMES.include?(key)
        end
        unless accelerator_environment.empty?
          fail!("#{label} service #{name} cannot request accelerator access through environment controls: #{accelerator_environment.sort.join(', ')}.")
        end
        if workload_service
          environment.each do |key, raw_value|
            next unless key.to_s.end_with?("_FILE")
            match = raw_value.to_s.match(%r{\A/run/secrets/([a-z][a-z0-9-]{1,62})\z})
            fail!("#{label} service #{name} has an invalid secret file path for #{key}.") unless match
            target = match[1]
            unless secret_targets.key?(target)
              fail!("#{label} service #{name} secret file #{key} references ungranted secret target #{target}.")
            end
          end
        end
      end
      fail!("#{label} service #{name} cannot share another PID namespace.") if service.key?("pid")
      if service.key?("user") && !service["user"].to_s.match?(/\A[1-9][0-9]{0,9}:[1-9][0-9]{0,9}\z/)
        fail!("#{label} service #{name} must use a canonical numeric uid:gid.")
      end
      if service.key?("logging") && service["logging"] != { "driver" => "local", "options" => { "max-size" => "10m", "max-file" => "3" } }
        fail!("#{label} service #{name} must use bounded local logging.")
      end
      if service.key?("blkio_config") && (!service["blkio_config"].is_a?(Hash) || service["blkio_config"].keys != ["weight"])
        fail!("#{label} service #{name} blkio_config must contain only the bounded global weight.")
      end
      if service.key?("mem_limit") && service["memswap_limit"] != service["mem_limit"]
        fail!("#{label} service #{name} must bind memswap_limit exactly to mem_limit.")
      end
      oom_controls = %w[oom_kill_disable oom_score_adj mem_swappiness].select { |key| service.key?(key) }
      fail!("#{label} service #{name} cannot override OOM or swappiness controls: #{oom_controls.join(', ')}.") unless oom_controls.empty?
      service_networks = service["networks"]
      unless service_networks.nil?
        entries = if service_networks.is_a?(Array)
                    service_networks.each_with_object({}) { |network, result| result[network] = nil }
                  else
                    service_networks
                  end
        fail!("#{label} service #{name} networks must be a sequence or mapping.") unless entries.is_a?(Hash)
        entries.each do |network, attachment|
          zone = network.to_s.delete_prefix(workload_network_prefix)
          if protected_networks.include?(network)
            fail!("#{label} service #{name} cannot join protected core network #{network}.")
          end
          if workload_id
            canonical_owner = canonical_network_owner!(network, all_workload_ids)
            unless canonical_owner == workload_id && network.is_a?(String) \
              && network.start_with?(workload_network_prefix) && WORKLOAD_NETWORK_ZONES.include?(zone)
              fail!("#{label} service #{name} uses foreign network #{network}.")
            end
          end
          unless attachment.nil? || (attachment.is_a?(Hash) && attachment.empty?)
            fail!("#{label} service #{name} cannot set network aliases or address overrides on #{network}.")
          end
        end
      end
      if PLATFORM_NETWORK_EXTENSION_ZONES.key?(name)
        unless service.keys.map(&:to_s).sort == ["networks"] && service_networks.is_a?(Hash) && !service_networks.empty?
          fail!("#{label} platform extension #{name} must contain only an explicit non-empty networks mapping.")
        end
        service_networks.each_key do |network|
          zone = network.to_s.delete_prefix(workload_network_prefix)
          canonical_owner = canonical_network_owner!(network, all_workload_ids)
          unless canonical_owner == workload_id && PLATFORM_NETWORK_EXTENSION_ZONES.fetch(name).include?(zone)
            fail!("#{label} platform extension #{name} cannot join workload zone #{zone}.")
          end
        end
        next
      end
      if workload_id && service.key?("volumes")
        mounts = service["volumes"]
        fail!("#{label} service #{name} volumes must use exact long syntax.") unless mounts.is_a?(Array)
        targets = {}
        mounts.each do |mount|
          exact = mount.is_a?(Hash) && mount.keys.sort == %w[source target type] \
            && mount["type"] == "volume" \
            && mount["source"].is_a?(String) \
            && mount["target"] == "/data"
          unless exact
            fail!("#{label} service #{name} volumes must be workload-owned exact long-syntax mounts targeting only /data.")
          end
          if protected_volumes.include?(mount["source"])
            fail!("#{label} service #{name} volume #{mount['source']} collides with a protected core volume.")
          end
          canonical_owner = canonical_volume_owner!(mount["source"], all_workload_ids)
          unless canonical_owner == workload_id
            fail!("#{label} service #{name} volume #{mount['source']} belongs to workload #{canonical_owner}, not #{workload_id}.")
          end
          fail!("#{label} service #{name} contains duplicate or overlapping volume targets.") if targets[mount["target"]]
          targets[mount["target"]] = true
        end
      end
      fail!("#{label} service #{name} cannot use env_file.") if service.key?("env_file")
      fail!("#{label} service #{name} cannot use extends.") if service.key?("extends")
      fail!("#{label} service #{name} cannot mount configs.") if service.key?("configs")
      fail!("#{label} service #{name} cannot use the Compose API socket.") if service.key?("use_api_socket")
      fail!("#{label} service #{name} cannot delegate execution to a provider.") if service.key?("provider")
      fail!("#{label} service #{name} cannot override the OCI runtime.") if service.key?("runtime")
      fail!("#{label} service #{name} cannot override the stop grace period.") if service.key?("stop_grace_period")
      device_controls = %w[devices device_cgroup_rules].select { |key| service.key?(key) }
      fail!("#{label} service #{name} cannot request host device access: #{device_controls.join(', ')}.") unless device_controls.empty?
      fail!("#{label} service #{name} cannot add supplemental groups.") if service.key?("group_add")
      accelerator_controls = %w[gpus device_requests].select { |key| service.key?(key) }
      reservations = service.dig("deploy", "resources", "reservations") if service["deploy"].is_a?(Hash)
      accelerator_controls << "deploy.resources.reservations.devices" if reservations.is_a?(Hash) && reservations.key?("devices")
      accelerator_controls << "deploy.resources.reservations.generic_resources" if reservations.is_a?(Hash) && reservations.key?("generic_resources")
      unless accelerator_controls.empty?
        fail!("#{label} service #{name} cannot request GPU or accelerator access: #{accelerator_controls.join(', ')}.")
      end
      fail!("#{label} service #{name} cannot define deploy controls.") if service.key?("deploy")
      lifecycle_hooks = %w[post_start pre_start pre_stop].select { |key| service.key?(key) }
      fail!("#{label} service #{name} cannot use lifecycle hooks: #{lifecycle_hooks.join(', ')}.") unless lifecycle_hooks.empty?
      fail!("#{label} service #{name} cannot set scale.") if service.key?("scale")
      fail!("#{label} service #{name} cannot set deploy.replicas.") if service["deploy"].is_a?(Hash) && service["deploy"].key?("replicas")
      fail!("#{label} service #{name} cannot set deploy.mode.") if service["deploy"].is_a?(Hash) && service["deploy"].key?("mode")
      fail!("#{label} service #{name} cannot use volumes_from.") if service.key?("volumes_from")
      if service.key?("healthcheck")
        healthcheck = service["healthcheck"]
        test = healthcheck["test"] if healthcheck.is_a?(Hash)
        exact_healthcheck = healthcheck.is_a?(Hash) && healthcheck.keys == ["test"] && test.is_a?(Array) \
          && test.length.between?(2, 16) && test.first == "CMD" \
          && test.drop(1).all? { |value| value.is_a?(String) && !value.empty? && value.bytesize <= 256 && !value.match?(/[\0\r\n]/) }
        unless exact_healthcheck
          fail!("#{label} service #{name} requires an exact bounded CMD healthcheck.")
        end
      end
      if service.key?("ulimits")
        ulimits = service["ulimits"]
        nofile = ulimits["nofile"] if ulimits.is_a?(Hash)
        exact_ulimits = ulimits.is_a?(Hash) && ulimits.keys == ["nofile"] && nofile.is_a?(Hash) \
          && nofile.keys.sort == %w[hard soft] \
          && nofile.values.all? { |value| value.is_a?(Integer) } \
          && nofile["soft"].between?(1024, 65_536) && nofile["hard"].between?(1024, 65_536) \
          && nofile["soft"] <= nofile["hard"]
        unless exact_ulimits
          fail!("#{label} service #{name} ulimits must contain only bounded nofile soft/hard values.")
        end
      end
      if service.key?("depends_on")
        dependencies = service["depends_on"]
        fail!("#{label} service #{name} depends_on must be an explicit mapping.") unless dependencies.is_a?(Hash)
        dependencies.each do |dependency, condition|
          allowed_dependency = model.fetch("services").key?(dependency) || PLATFORM_DEPENDENCIES.include?(dependency)
          fail!("#{label} service #{name} depends on unauthorized service #{dependency}.") unless allowed_dependency
          unless condition.is_a?(Hash) \
            && (condition.keys.map(&:to_s) - %w[condition required restart]).empty? \
            && %w[service_started service_healthy].include?(condition["condition"]) \
            && (!condition.key?("required") || condition["required"] == true) \
            && (!condition.key?("restart") || condition["restart"] == false)
            fail!("#{label} service #{name} dependency #{dependency} must use a bounded required start/health condition.")
          end
        end
      end
      unsupported_fields = service.keys.map(&:to_s) - WORKLOAD_SERVICE_KEYS
      unless unsupported_fields.empty?
        fail!("#{label} service #{name} uses unsupported Compose service fields: #{unsupported_fields.sort.join(', ')}.")
      end
      if workload_id && service["security_opt"] != ["no-new-privileges:true"]
        fail!("#{label} service #{name} security_opt must be exactly [no-new-privileges:true].")
      end
    end
    if workload_id
      workload_services = model.fetch("services").reject { |name, _service| PLATFORM_NETWORK_EXTENSION_ZONES.key?(name) }
      referenced_volumes = workload_services.values.flat_map do |service|
        Array(service["volumes"]).map do |mount|
          mount["source"] if mount.is_a?(Hash) && mount["type"] == "volume"
        end.compact
      end.uniq.sort
      referenced_secrets = workload_services.values.flat_map do |service|
        Array(service["secrets"]).map { |entry| entry.is_a?(Hash) ? entry["source"] : entry }
      end.compact.uniq.sort
      referenced_networks = model.fetch("services").values.flat_map do |service|
        service_networks = service["networks"]
        service_networks.is_a?(Hash) ? service_networks.keys : Array(service_networks)
      end.uniq.sort
      workload_referenced_networks = workload_services.values.flat_map do |service|
        service_networks = service["networks"]
        service_networks.is_a?(Hash) ? service_networks.keys : Array(service_networks)
      end.uniq.sort
      declared_volumes = (volumes || {}).keys.map(&:to_s).sort
      declared_secret_names = (secrets || {}).keys.map(&:to_s).sort
      declared_networks = (networks || {}).keys.map(&:to_s).sort
      unless referenced_volumes == declared_volumes
        fail!("#{label} workload volumes must be exactly declared and referenced.")
      end
      unless referenced_secrets == declared_secret_names && declared_secret_names == declared_secrets.sort
        fail!("#{label} workload secrets must be exactly manifest-owned, declared, and referenced.")
      end
      unless referenced_networks == declared_networks
        fail!("#{label} workload networks must be exactly declared and referenced.")
      end
      unless workload_referenced_networks == declared_networks
        fail!("#{label} every workload network requires a signed workload service consumer.")
      end
    end
    true
  end

  def stable_read(path, label)
    flags = File::RDONLY
    flags |= File::NOFOLLOW if File.const_defined?(:NOFOLLOW)
    File.open(path, flags) do |file|
      before = file.stat
      fail!("#{label} must be a regular file.") unless before.file?
      bytes = file.read
      after = file.stat
      identity = %i[dev ino size mtime].all? { |field| before.public_send(field) == after.public_send(field) }
      fail!("#{label} changed while being read.") unless identity
      bytes
    end
  end

  def top_level_mapping_names(bytes, key, label)
    stream = Psych.parse_stream(bytes, filename: label)
    fail!("#{label} must contain exactly one YAML document.") unless stream.children.length == 1
    root = stream.children.first.root
    fail!("#{label} must contain a mapping.") unless root.is_a?(Psych::Nodes::Mapping)
    matches = root.children.each_slice(2).select { |name, _value| name.is_a?(Psych::Nodes::Scalar) && name.value == key }
    fail!("#{label} contains duplicate top-level #{key}.") if matches.length > 1
    return [] if matches.empty?
    mapping = matches.first.fetch(1)
    fail!("#{label} top-level #{key} must be a mapping.") unless mapping.is_a?(Psych::Nodes::Mapping)
    mapping.children.each_slice(2).map do |name, _value|
      fail!("#{label} #{key} must use scalar keys.") unless name.is_a?(Psych::Nodes::Scalar)
      name.value.to_s
    end
  rescue Psych::Exception => e
    fail!("#{label} is not valid YAML: #{e.message}")
  end

  def validate_lock(lock)
    fail!("Hosted workload lock schema is not supported.") unless lock["version"] == 4 && lock["validatorVersion"] == "hosted-contract-v4"
    fail!("Hosted workload lock must be resolved.") unless lock["state"] == "resolved"
    workload_ids = validate_workload_id_set!(lock["workloads"])
    canonical_owners = {
      "services" => {},
      "secrets" => {},
      "volumes" => {},
      "networks" => {}
    }
    lock.fetch("workloads").each do |workload|
      workload.fetch("services").each do |service|
        add_canonical_owner!(canonical_owners.fetch("services"), "Workload service", service.fetch("name"), workload.fetch("id"))
      end
      workload.fetch("secrets").each do |secret_name|
        add_canonical_owner!(canonical_owners.fetch("secrets"), "Workload secret", secret_name, workload.fetch("id"))
      end
    end
    generation = File.realpath(lock.fetch("snapshotGeneration"))
    protected_resources = {
      "configs" => [],
      "secrets" => [],
      "services" => [],
      "volumes" => [],
      "networks" => []
    }
    lock.fetch("files").select { |record| record["kind"] == "core-compose" }.each do |record|
      bytes = stable_read(record.fetch("path"), "core Compose source")
      fail!("Core Compose digest changed.") unless Digest::SHA256.hexdigest(bytes) == record.fetch("sha256")
      protected_resources.each_key do |resource_type|
        protected_resources.fetch(resource_type).concat(
          top_level_mapping_names(bytes, resource_type, record.fetch("path"))
        )
      end
    end
    protected_resources.transform_values! { |names| names.uniq.sort }
    protected_networks = protected_resources.fetch("networks")
    receipts = lock.fetch("workloads").map do |workload|
      workload_id = workload.fetch("id")
      records = lock.fetch("files").select { |item| item["kind"] == "workload-compose" && item["workloadId"] == workload_id }
      fail!("#{workload_id} must have exactly one workload-compose snapshot record.") unless records.length == 1
      record = records.fetch(0)
      compose_path = File.realpath(record.fetch("path"))
      fail!("#{workload_id} compose path is outside the snapshot generation.") unless File.dirname(compose_path) == generation
      fail!("#{workload_id} compose path differs from the lock workload entry.") unless compose_path == workload.fetch("composePath")
      bytes = stable_read(compose_path, "#{workload_id} Compose source")
      fail!("#{workload_id} Compose digest changed.") unless Digest::SHA256.hexdigest(bytes) == record.fetch("sha256")
      model = parse_compose(bytes, "#{workload_id} Compose source")
      validate_source_model(
        model,
        "#{workload_id} Compose source",
        workload_id: workload_id,
        workload_ids: workload_ids,
        project_name: lock.fetch("projectName"),
        declared_secrets: workload.fetch("secrets"),
        protected_networks: protected_networks,
        protected_resources: protected_resources
      )
      declared_service_names = workload.fetch("services").map { |service| service.fetch("name") }.sort
      source_service_names = model.fetch("services").keys.map(&:to_s).sort
      fail!("#{workload_id} Compose source must contain every and only declared workload service plus allowed platform extension stubs.") \
        unless (declared_service_names - source_service_names).empty? \
          && (source_service_names - declared_service_names - PLATFORM_NETWORK_EXTENSION_ZONES.keys).empty?
      platform_extensions = (source_service_names - declared_service_names).map do |service_name|
        {
          "serviceName" => service_name,
          "networkNames" => model.fetch("services").fetch(service_name).fetch("networks").keys.map(&:to_s).sort
        }
      end
      (model["volumes"] || {}).each_key do |volume_name|
        add_canonical_owner!(canonical_owners.fetch("volumes"), "Workload volume", volume_name, workload_id)
      end
      (model["networks"] || {}).each_key do |network_name|
        add_canonical_owner!(canonical_owners.fetch("networks"), "Workload network", network_name, workload_id)
      end
      router_extension = platform_extensions.find { |item| item.fetch("serviceName") == "project-router" }
      if router_extension
        router_extension.fetch("networkNames").each do |network_name|
          routed_consumers = workload.fetch("services").select do |service|
            rendered_networks = model.fetch("services").fetch(service.fetch("name"))["networks"]
            rendered_network_names = rendered_networks.is_a?(Hash) ? rendered_networks.keys : Array(rendered_networks)
            !Array(service["routes"]).empty? \
              && rendered_network_names.include?(network_name)
          end
          if routed_consumers.empty?
            fail!("#{workload_id} router ingress network #{network_name} has no signed routed workload consumer.")
          end
        end
      end
      {
        "workloadId" => workload_id,
        "composeSha256" => record.fetch("sha256"),
        "topLevelKeys" => model.keys.map(&:to_s).sort,
        "serviceNames" => declared_service_names,
        "configNames" => (model["configs"] || {}).keys.map(&:to_s).sort,
        "secretNames" => (model["secrets"] || {}).keys.map(&:to_s).sort,
        "volumeNames" => (model["volumes"] || {}).keys.map(&:to_s).sort,
        "platformExtensions" => platform_extensions.sort_by { |item| item.fetch("serviceName") },
        "networkNames" => (model["networks"] || {}).keys.map(&:to_s).sort
      }
    end
    receipt = {
      "policyVersion" => VERSION,
      "controls" => CONTROLS,
      "protectedNetworkNames" => protected_networks,
      "protectedResourceNames" => protected_resources,
      "workloadContentSha256" => lock.fetch("workloadContentSha256"),
      "workloads" => receipts.sort_by { |item| item.fetch("workloadId") }
    }
    lock["rawPolicyVersion"] = VERSION
    lock["rawPolicyControls"] = CONTROLS
    lock["rawPolicyWorkloadContentSha256"] = lock.fetch("workloadContentSha256")
    lock["rawPolicyReceipt"] = receipt
    lock["rawPolicySha256"] = Digest::SHA256.hexdigest(JSON.generate(stable(receipt)))
    lock
  end

  def validate_file(lock_path)
    bytes = stable_read(lock_path, "hosted workload lock")
    lock = JSON.parse(bytes)
    validate_lock(lock)
    temporary = "#{lock_path}.raw-policy-#{Process.pid}"
    File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
      file.write("#{JSON.pretty_generate(lock)}\n")
      file.flush
      file.fsync
    end
    File.chmod(0o600, temporary)
    File.rename(temporary, lock_path)
    File.open(File.dirname(lock_path), File::RDONLY) { |directory| directory.fsync }
  ensure
    File.delete(temporary) if defined?(temporary) && temporary && File.exist?(temporary)
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    options = {}
    OptionParser.new do |parser|
      parser.on("--lock PATH") { |value| options[:lock] = value }
    end.parse!
    HostedWorkloadSourcePolicy.fail!("Usage: hosted-workload-source-policy.rb --lock PATH") unless options[:lock]
    HostedWorkloadSourcePolicy.validate_file(File.expand_path(options[:lock]))
  rescue StandardError => e
    warn(e.message)
    exit(1)
  end
end

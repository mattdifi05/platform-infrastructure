#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "json"
require "optparse"
require "psych"

module HostedWorkloadSourcePolicy
  VERSION = "hosted-raw-v1"
  CONTROLS = %w[bind-bounded-local-logging bind-network-identity bind-network-topology bind-no-swap-oom-policy bind-owned-secret-aliases bind-owned-volumes bind-private-pid-numeric-user deny-api-socket deny-compose-interpolation deny-device-access deny-env-file deny-extends deny-file-configs deny-gpu-access deny-include deny-inline-configs deny-lifecycle-hooks deny-local-volume-options deny-providers deny-runtime-identity-labels deny-runtime-overrides deny-scaling deny-stop-grace-overrides deny-supplemental-groups deny-volumes-from].freeze
  MAX_COMPOSE_BYTES = 1_048_576
  STANDARD_TAG_PREFIX = "tag:yaml.org,2002:"
  WORKLOAD_NETWORK_ZONES = %w[ingress postgres cache bus identity storage observability egress].freeze

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

  def validate_source_model(model, label, workload_id: nil, project_name: nil, declared_secrets: [])
    fail!("#{label} cannot use top-level include.") if model.key?("include")
    configs = model["configs"]
    fail!("#{label} configs must be a mapping.") if !configs.nil? && !configs.is_a?(Hash)
    (configs || {}).each do |name, definition|
      fail!("#{label} config #{name} cannot use a file source.") if definition.is_a?(Hash) && definition.key?("file")
      if definition.is_a?(Hash) && (definition.key?("content") || definition.key?("environment"))
        fail!("#{label} config #{name} cannot use inline or host-environment content.")
      end
    end
    secrets = model["secrets"]
    fail!("#{label} secrets must be a mapping.") if !secrets.nil? && !secrets.is_a?(Hash)
    (secrets || {}).each do |name, definition|
      next unless workload_id
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
        fail!("#{label} volume #{name} is not workload-prefixed.") unless name.start_with?("#{workload_id}_")
        if definition.is_a?(Hash) && (definition["external"] == true || definition.key?("name"))
          fail!("#{label} volume #{name} cannot alias an external or foreign physical volume.")
        end
      end
      if definition.is_a?(Hash) && definition.key?("driver_opts")
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
      fail!("#{label} service #{name} cannot share another PID namespace.") if service.key?("pid")
      if service.key?("user") && !service["user"].to_s.match?(/\A[1-9][0-9]{0,9}:[1-9][0-9]{0,9}\z/)
        fail!("#{label} service #{name} must use a canonical numeric uid:gid.")
      end
      if service.key?("logging") && service["logging"] != { "driver" => "local", "options" => { "max-size" => "10m", "max-file" => "3" } }
        fail!("#{label} service #{name} must use bounded local logging.")
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
          if workload_id && (!network.is_a?(String) || !network.start_with?(workload_network_prefix) || !WORKLOAD_NETWORK_ZONES.include?(zone))
            fail!("#{label} service #{name} uses foreign network #{network}.")
          end
          unless attachment.nil? || (attachment.is_a?(Hash) && attachment.empty?)
            fail!("#{label} service #{name} cannot set network aliases or address overrides on #{network}.")
          end
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
      unless accelerator_controls.empty?
        fail!("#{label} service #{name} cannot request GPU or accelerator access: #{accelerator_controls.join(', ')}.")
      end
      lifecycle_hooks = %w[post_start pre_start pre_stop].select { |key| service.key?(key) }
      fail!("#{label} service #{name} cannot use lifecycle hooks: #{lifecycle_hooks.join(', ')}.") unless lifecycle_hooks.empty?
      fail!("#{label} service #{name} cannot set scale.") if service.key?("scale")
      fail!("#{label} service #{name} cannot set deploy.replicas.") if service["deploy"].is_a?(Hash) && service["deploy"].key?("replicas")
      fail!("#{label} service #{name} cannot set deploy.mode.") if service["deploy"].is_a?(Hash) && service["deploy"].key?("mode")
      fail!("#{label} service #{name} cannot use volumes_from.") if service.key?("volumes_from")
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

  def validate_lock(lock)
    fail!("Hosted workload lock schema is not supported.") unless lock["version"] == 2 && lock["validatorVersion"] == "hosted-contract-v2"
    fail!("Hosted workload lock must be resolved.") unless lock["state"] == "resolved"
    generation = File.realpath(lock.fetch("snapshotGeneration"))
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
        project_name: lock.fetch("projectName"),
        declared_secrets: workload.fetch("secrets")
      )
      {
        "workloadId" => workload_id,
        "composeSha256" => record.fetch("sha256"),
        "topLevelKeys" => model.keys.map(&:to_s).sort,
        "serviceNames" => model.fetch("services").keys.map(&:to_s).sort,
        "networkNames" => (model["networks"] || {}).keys.map(&:to_s).sort
      }
    end
    receipt = {
      "policyVersion" => VERSION,
      "controls" => CONTROLS,
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

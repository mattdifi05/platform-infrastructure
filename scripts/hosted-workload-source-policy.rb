#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "json"
require "optparse"
require "psych"

module HostedWorkloadSourcePolicy
  VERSION = "hosted-raw-v1"
  CONTROLS = %w[bind-owned-secret-aliases bind-owned-volumes deny-api-socket deny-device-access deny-env-file deny-extends deny-file-configs deny-gpu-access deny-include deny-lifecycle-hooks deny-local-volume-options deny-providers deny-runtime-overrides deny-scaling deny-stop-grace-overrides deny-supplemental-groups deny-volumes-from].freeze
  MAX_COMPOSE_BYTES = 1_048_576
  STANDARD_TAG_PREFIX = "tag:yaml.org,2002:"

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
    model.fetch("services").each do |name, service|
      fail!("#{label} service #{name} must be a mapping.") unless service.is_a?(Hash)
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
        "serviceNames" => model.fetch("services").keys.map(&:to_s).sort
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

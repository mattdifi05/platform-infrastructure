require "yaml"
require "json"
require "pathname"

root = Pathname.new(ENV.fetch("ROOT")).realpath
files = %w[
  compose.yaml
  compose.secrets.yaml
  compose.waf.yaml
  compose.vps.yaml
  compose.vps-waf.yaml
  compose.backup-scheduler.yaml
  compose.runtime.yaml
  compose.networks.yaml
  compose.runtime-isolation.yaml
]
env = {
  "COMPOSE_PROJECT_NAME" => "platform_infra_vps",
  "DOMAIN" => "fixture.invalid",
  "PHP_PROJECTS_DIR" => "../compose-source",
  "PROJECT_SOURCE_DIR" => "../compose-source",
  "HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE" =>
    root.join("config/no-hosted-workloads.lock.json").to_s,
  "ALERT_EMAIL_TO" => "qa@fixture.invalid",
  "MAILER_FROM" => "qa@fixture.invalid",
  "MAILER_REPLY_TO" => "qa@fixture.invalid",
  "SMTP_HOST" => "smtp.fixture.invalid",
  "SMTP_USER" => "qa",
}

def tagged_paths(text)
  top = nil
  service = nil
  paths = {}
  text.each_line do |line|
    next if line.lstrip.start_with?("#") || line.strip.empty?
    indent = line[/\A */].length
    if indent == 0 && (match = line.match(/^([A-Za-z0-9_.-]+):/))
      top = match[1]
      service = nil
    elsif top == "services" && indent == 2 &&
          (match = line.match(/^  ([A-Za-z0-9_.-]+):/))
      service = match[1]
    elsif top == "services" && service && indent == 4 &&
          (match = line.match(/^    ([A-Za-z0-9_.-]+):\s+!(override|reset)\b/))
      paths[["services", service, match[1]]] = match[2]
    end
  end
  paths
end

def volume_target(item)
  return item["target"] if item.is_a?(Hash)
  parts = item.to_s.split(":")
  parts.pop if parts.last&.match?(/\A(?:ro|rw)(?:,|\z)/)
  parts.last || item.to_s
end

def unique_key(field, item)
  case field
  when "volumes"
    volume_target(item)
  when "secrets", "configs"
    item.is_a?(Hash) ? (item["target"] || item["source"]) : item.to_s
  else
    item.to_s
  end
end

def copy(value)
  Marshal.load(Marshal.dump(value))
end

def merge_value(left, right, path, tags)
  return copy(right) if tags.key?(path)
  if left.is_a?(Hash) && right.is_a?(Hash)
    merged = copy(left)
    right.each do |key, value|
      merged[key] = merged.key?(key) ?
        merge_value(merged[key], value, path + [key], tags) : copy(value)
    end
    return merged
  end
  if left.is_a?(Array) && right.is_a?(Array)
    field = path.last
    return copy(right) if %w[command entrypoint test].include?(field)
    if %w[volumes secrets configs ports].include?(field)
      merged = copy(left)
      index = {}
      merged.each_with_index { |item, idx| index[unique_key(field, item)] = idx }
      right.each do |item|
        key = unique_key(field, item)
        if index.key?(key)
          merged[index[key]] = copy(item)
        else
          index[key] = merged.length
          merged << copy(item)
        end
      end
      return merged
    end
    return copy(left + right)
  end
  copy(right)
end

def operator_split(expression)
  depth = 0
  (0...(expression.length - 1)).each do |idx|
    if expression[idx, 2] == "${"
      depth += 1
      next
    end
    if expression[idx] == "}" && depth.positive?
      depth -= 1
      next
    end
    if depth.zero? && [":-", ":?"].include?(expression[idx, 2])
      return [expression[0...idx], expression[idx, 2], expression[(idx + 2)..]]
    end
  end
  [expression, nil, nil]
end

def expand_string(input, env)
  sentinel = "\u0001DOLLAR\u0001"
  value = input.gsub("$$", sentinel)
  loop do
    start = value.index("${")
    break unless start
    depth = 1
    cursor = start + 2
    while cursor < value.length && depth.positive?
      if value[cursor, 2] == "${"
        depth += 1
        cursor += 2
      elsif value[cursor] == "}"
        depth -= 1
        cursor += 1
      else
        cursor += 1
      end
    end
    raise "unclosed interpolation" unless depth.zero?
    expression = value[(start + 2)...(cursor - 1)]
    key, operator, fallback = operator_split(expression)
    observed = env[key]
    replacement =
      if observed && !observed.empty?
        observed
      elsif operator == ":-"
        expand_string(fallback, env)
      elsif operator == ":?"
        raise "required environment #{key}"
      else
        ""
      end
    value = value[0...start] + replacement + value[cursor..]
  end
  value.gsub(sentinel, "$$")
end

def interpolate(value, env)
  case value
  when Hash
    value.to_h { |key, nested| [key, interpolate(nested, env)] }
  when Array
    value.map { |nested| interpolate(nested, env) }
  when String
    expand_string(value, env)
  else
    value
  end
end

def byte_count(value)
  return value unless value.is_a?(String)
  match = value.match(/\A([0-9]+)([kmgt])b?\z/i)
  return value unless match
  powers = { "k" => 1, "m" => 2, "g" => 3, "t" => 4 }
  match[1].to_i * (1024**powers.fetch(match[2].downcase))
end

def normalize_port(value)
  return value if value.is_a?(Hash)
  raw, protocol = value.to_s.split("/", 2)
  parts = raw.split(":")
  target = Integer(parts.pop, 10)
  published = parts.empty? ? nil : parts.pop
  host_ip = parts.join(":")
  result = { "target" => target, "protocol" => protocol || "tcp" }
  result["published"] = published if published
  result["host_ip"] = host_ip unless host_ip.empty?
  result
end

def normalize_mount(value, root)
  return value if value.is_a?(Hash)
  parts = value.to_s.split(":")
  mode = parts.last&.match?(/\A(?:ro|rw)(?:,.*)?\z/) ? parts.pop : nil
  target = parts.pop
  source = parts.join(":")
  bind = source.start_with?("/", "./", "../", ".", "..")
  normalized_source = bind ? root.join(source).cleanpath.to_s : source
  result = {
    "type" => bind ? "bind" : "volume",
    "source" => normalized_source,
    "target" => target,
  }
  result["read_only"] = true if mode&.split(",")&.include?("ro")
  result
end

def normalize_service(service, root)
  service = copy(service)
  if service["environment"].is_a?(Hash)
    service["environment"] =
      service["environment"].to_h { |key, value| [key.to_s, value.nil? ? "" : value.to_s] }
  end
  service["labels"] = {} if service["labels"].is_a?(Array) && service["labels"].empty?
  service.delete("profiles") if service["profiles"].is_a?(Array) && service["profiles"].empty?
  if service["networks"].is_a?(Array)
    service["networks"] = service["networks"].to_h { |name| [name, nil] }
  end
  if service["depends_on"].is_a?(Array)
    service["depends_on"] = service["depends_on"].to_h do |name|
      [name, { "condition" => "service_started", "required" => true, "restart" => false }]
    end
  elsif service["depends_on"].is_a?(Hash)
    service["depends_on"].each_value do |definition|
      next unless definition.is_a?(Hash)
      definition["condition"] ||= "service_started"
      definition["required"] = true unless definition.key?("required")
      definition["restart"] = false unless definition.key?("restart")
    end
  end
  service["ports"] = service["ports"].map { |port| normalize_port(port) } if service["ports"].is_a?(Array)
  service["volumes"] = service["volumes"].map { |mount| normalize_mount(mount, root) } if service["volumes"].is_a?(Array)
  service["expose"] = service["expose"].map(&:to_s) if service["expose"].is_a?(Array)
  service["group_add"] = service["group_add"].map(&:to_s) if service["group_add"].is_a?(Array)
  %w[mem_limit mem_reservation memswap_limit].each do |key|
    service[key] = byte_count(service[key]) if service.key?(key)
  end
  if service["build"].is_a?(Hash)
    service["build"]["context"] = root.join(service["build"]["context"]).cleanpath.to_s
    if service["build"]["args"].is_a?(Hash)
      service["build"]["args"] =
        service["build"]["args"].to_h { |key, value| [key, value.to_s] }
    end
  end
  service
end

model = {}
files.each do |relative|
  text = root.join(relative).read
  tags = tagged_paths(text)
  parsed = YAML.safe_load(text.gsub(/!(?:override|reset)\b/, ""), aliases: true)
  model = merge_value(model, parsed, [], tags)
end
if ENV["RAW_OUT"]
  File.write(ENV.fetch("RAW_OUT"), JSON.generate(model) + "\n")
end
model = interpolate(model, env)
model.delete_if { |key, _| key.start_with?("x-") }
services = model.fetch("services").select do |_name, service|
  profiles = service["profiles"]
  !profiles.is_a?(Array) || profiles.empty? || profiles.include?("backup")
end
model["services"] =
  services.to_h { |name, service| [name, normalize_service(service, root)] }
model["name"] = "platform_infra_vps"
model.fetch("secrets", {}).each_value do |definition|
  if definition.is_a?(Hash) && definition["file"]
    definition["file"] = root.join(definition["file"]).cleanpath.to_s
  end
end
File.write(ENV.fetch("GOLDEN_OUT"), JSON.generate(model) + "\n")

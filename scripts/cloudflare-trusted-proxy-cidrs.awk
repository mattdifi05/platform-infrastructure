BEGIN {
  if (family != "ipv4" && family != "ipv6") fail("unsupported address family")
}

function fail(reason) {
  print "Invalid " family " CIDR in " source_label ": " reason > "/dev/stderr"
  exit 1
}

function hex_value(text,    digits, value, index_value, position, character) {
  digits = "0123456789abcdef"
  value = 0
  for (position = 1; position <= length(text); position += 1) {
    character = substr(text, position, 1)
    index_value = index(digits, character) - 1
    if (index_value < 0) fail("invalid IPv6 hextet")
    value = value * 16 + index_value
  }
  return value
}

function canonical_ipv4(cidr,    parts, address, prefix_text, prefix, octets, position, octet, value, block, network, output, divisor) {
  if (split(cidr, parts, "/") != 2) fail("IPv4 network must contain one prefix")
  address = parts[1]
  prefix_text = parts[2]
  if (prefix_text !~ /^[0-9]+$/ || (prefix_text + 0) < 0 || (prefix_text + 0) > 32) fail("invalid IPv4 prefix")
  prefix = prefix_text + 0
  if (split(address, octets, /\./) != 4) fail("invalid IPv4 address")
  value = 0
  for (position = 1; position <= 4; position += 1) {
    if (octets[position] !~ /^[0-9]+$/ || (octets[position] + 0) < 0 || (octets[position] + 0) > 255) fail("invalid IPv4 octet")
    octet = octets[position] + 0
    value = value * 256 + octet
  }
  block = 2 ^ (32 - prefix)
  network = int(value / block) * block
  output = ""
  for (position = 1; position <= 4; position += 1) {
    divisor = 2 ^ (8 * (4 - position))
    octet = int(network / divisor)
    network -= octet * divisor
    output = output (position == 1 ? "" : ".") octet
  }
  return output "/" prefix
}

function canonical_ipv6(cidr,    parts, address, prefix_text, prefix, compression, remainder, left_text, right_text, left, right, left_count, right_count, groups, group_count, position, token, remaining, block, run_start, run_length, best_start, best_length, output) {
  if (split(cidr, parts, "/") != 2) fail("IPv6 network must contain one prefix")
  address = tolower(parts[1])
  prefix_text = parts[2]
  if (prefix_text !~ /^[0-9]+$/ || (prefix_text + 0) < 0 || (prefix_text + 0) > 128) fail("invalid IPv6 prefix")
  prefix = prefix_text + 0
  if (address !~ /^[0-9a-f:]+$/) fail("invalid IPv6 address")
  compression = index(address, "::")
  if (compression > 0) {
    remainder = substr(address, compression + 2)
    if (index(remainder, "::") > 0) fail("multiple IPv6 compression markers")
    left_text = substr(address, 1, compression - 1)
    right_text = remainder
    left_count = left_text == "" ? 0 : split(left_text, left, ":")
    right_count = right_text == "" ? 0 : split(right_text, right, ":")
    if (left_count + right_count >= 8) fail("IPv6 compression marker does not compress a group")
    group_count = 0
    for (position = 1; position <= left_count; position += 1) groups[++group_count] = left[position]
    while (group_count < 8 - right_count) groups[++group_count] = "0"
    for (position = 1; position <= right_count; position += 1) groups[++group_count] = right[position]
  } else {
    group_count = split(address, groups, ":")
    if (group_count != 8) fail("IPv6 address must contain eight groups or one compression marker")
  }
  if (group_count != 8) fail("invalid IPv6 group count")
  for (position = 1; position <= 8; position += 1) {
    token = groups[position]
    if (token !~ /^[0-9a-f]{1,4}$/) fail("invalid IPv6 hextet")
    groups[position] = hex_value(token)
    remaining = prefix - ((position - 1) * 16)
    if (remaining <= 0) groups[position] = 0
    else if (remaining < 16) {
      block = 2 ^ (16 - remaining)
      groups[position] = int(groups[position] / block) * block
    }
  }

  best_start = 0
  best_length = 0
  run_start = 0
  run_length = 0
  for (position = 1; position <= 9; position += 1) {
    if (position <= 8 && groups[position] == 0) {
      if (run_length == 0) run_start = position
      run_length += 1
    } else {
      if (run_length >= 2 && run_length > best_length) {
        best_start = run_start
        best_length = run_length
      }
      run_length = 0
    }
  }

  output = ""
  position = 1
  while (position <= 8) {
    if (position == best_start) {
      output = output "::"
      position += best_length
      continue
    }
    if (output != "" && substr(output, length(output), 1) != ":") output = output ":"
    output = output sprintf("%x", groups[position])
    position += 1
  }
  if (output == "") output = "::"
  return output "/" prefix
}

/^[[:space:]]*$/ { next }
{
  value = $0
  gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
  canonical = family == "ipv4" ? canonical_ipv4(value) : canonical_ipv6(value)
  if (seen[canonical]++) fail("duplicate canonical network")
  print canonical
}

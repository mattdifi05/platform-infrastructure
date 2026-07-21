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
end

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
end

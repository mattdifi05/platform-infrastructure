import assert from "node:assert/strict";
import test from "node:test";

import { countryOptions } from "./countries";

test("country list covers the full selectable ISO-style country set", () => {
  const countries = countryOptions("en-US");
  const countryValues = new Set<string>(countries.map((country) => country.value));
  assert.equal(countryValues.size >= 249, true);
  for (const country of ["IT", "US", "DE", "FR", "ES", "GB", "BR", "JP", "ZA", "XK"]) {
    assert.equal(countryValues.has(country), true, country);
  }
});

test("country options are localized with display names", () => {
  const countries = countryOptions("it-IT");
  const italy = countries.find((country) => country.value === "IT");
  assert.equal(italy?.label, "Italia");
  assert.equal(countries.length, countryOptions("en-US").length);
});

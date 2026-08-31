#!/usr/bin/env node
import fs from "node:fs";

import { assertBrokerStateReady, loadLocalPrivateTrust } from "./local-private-docker-action-broker.mjs";

const socketPath = process.env.DOCKER_ACTION_BROKER_SOCKET || "/run/platform/docker-action-broker/broker.sock";
const stateDir = process.env.DOCKER_ACTION_BROKER_STATE_DIR || "/var/lib/platform/docker-action-broker";

try {
  loadLocalPrivateTrust(process.env);
  const socket = fs.lstatSync(socketPath);
  if (!socket.isSocket() || socket.isSymbolicLink()) throw new Error("broker socket is not ready");
  assertBrokerStateReady(stateDir);
  process.stdout.write("ready\n");
} catch (error) {
  process.stderr.write(`${error.message ?? error}\n`);
  process.exitCode = 1;
}

// Registry of every native client-side op, keyed by op id.
import { ops as encoding } from "./encoding.js";
import { ops as hashing } from "./hashing.js";
import { ops as cryptoOps } from "./crypto.js";
import { ops as text } from "./text.js";
import { ops as data } from "./data.js";
import { ops as network } from "./network.js";
export const registry = { ...encoding, ...hashing, ...cryptoOps, ...text, ...data, ...network };

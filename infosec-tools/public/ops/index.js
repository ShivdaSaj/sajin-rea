// Registry of every native client-side op, keyed by op id.
import { ops as encoding } from "./encoding.js";
import { ops as hashing } from "./hashing.js";
import { ops as cryptoOps } from "./crypto.js";
import { ops as text } from "./text.js";
import { ops as data } from "./data.js";
import { ops as network } from "./network.js";
import { ops as hashing2 } from "./hashing2.js";
import { ops as cipher2 } from "./cipher2.js";
import { ops as pki } from "./pki.js";
import { ops as data2 } from "./data2.js";
import { ops as convert } from "./convert.js";
import { ops as net2 } from "./net2.js";
import { ops as reference } from "./reference.js";
export const registry = { ...encoding, ...hashing, ...cryptoOps, ...text, ...data, ...network, ...hashing2, ...cipher2, ...pki, ...data2, ...convert, ...net2, ...reference };

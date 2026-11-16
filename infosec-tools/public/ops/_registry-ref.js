// Late-bound access to the op registry, for ops (like Magic) that call other ops.
let REG = {};
export const registry = () => REG;
export const setRegistry = (r) => { REG = r; };

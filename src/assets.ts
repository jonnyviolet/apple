import icon2x from "../template/icon@2x.png";
import icon3x from "../template/icon@3x.png";
import strip3x from "../template/strip@3x.png";

/**
 * Images bundled into every signed pass. Filenames are the ones Wallet looks
 * for, so they must match exactly. These mirror the Pass Designer export that
 * is distributed, so an update never changes the artwork.
 */
export const ASSETS: Record<string, ArrayBuffer> = {
  "icon@2x.png": icon2x,
  "icon@3x.png": icon3x,
  "strip@3x.png": strip3x,
};

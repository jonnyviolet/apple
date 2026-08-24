import icon from "../template/icon.png";
import icon2x from "../template/icon@2x.png";
import icon3x from "../template/icon@3x.png";
import strip3x from "../template/strip@3x.png";

/**
 * Images bundled into every signed pass. Filenames are the ones Wallet looks
 * for, so they must match exactly. Replace the files in template/ with your
 * Pass Designer exports; `icon.png` is required even though Pass Designer only
 * emits @2x/@3x.
 */
export const ASSETS: Record<string, ArrayBuffer> = {
  "icon.png": icon,
  "icon@2x.png": icon2x,
  "icon@3x.png": icon3x,
  "strip@3x.png": strip3x,
};

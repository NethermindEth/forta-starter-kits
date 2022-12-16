const { getAaveV2Flashloan } = require("./detectors/aave-v2-detector");
const { getAaveV3Flashloan } = require("./detectors/aave-v3-detector");
const { getDydxFlashloan } = require("./detectors/dydx-detector");
const { getEulerFlashloan } = require("./detectors/euler-detector");
const { getIronBankFlashloan } = require("./detectors/iron-bank-detector");
const { getMakerFlashloan } = require("./detectors/maker-detector");
const { getBalancerFlashloan } = require("./detectors/balancer-detector");
const { getUniswapV2Flashloan } = require("./detectors/uniswap-v2-detector");
const { getUniswapV3Flashloan } = require("./detectors/uniswap-v3-detector");

module.exports = {
  // Returns an array of protocols from which a flashloan was taken
  async getFlashloans(txEvent) {
    const flashloanProtocols = [];
    const aaveV2Flashloans = getAaveV2Flashloan(txEvent);
    const aaveV3Flashloans = getAaveV3Flashloan(txEvent);
    const dydxFlashloans = await getDydxFlashloan(txEvent);
    const eulerFlashloans = getEulerFlashloan(txEvent);
    const ironBankFlashloans = await getIronBankFlashloan(txEvent);
    const makerFlashloans = getMakerFlashloan(txEvent);
    const uniswapV2Flashloans = await getUniswapV2Flashloan(txEvent);
    const uniswapV3Flashloans = await getUniswapV3Flashloan(txEvent);
    const balancerFlashloans = getBalancerFlashloan(txEvent);

    flashloanProtocols.push(
      ...aaveV2Flashloans,
      ...aaveV3Flashloans,
      ...dydxFlashloans,
      ...eulerFlashloans,
      ...ironBankFlashloans,
      ...makerFlashloans,
      ...uniswapV2Flashloans,
      ...uniswapV3Flashloans,
      ...balancerFlashloans
    );

    return flashloanProtocols;
  },
};

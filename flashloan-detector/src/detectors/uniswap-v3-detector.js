const { ethers, getEthersProvider } = require("forta-agent");

const functionSignature = "function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data)";
const swapAbi = "function swap(address recipient, bool zeroForOne, int256 amountSpecified, uint160 sqrtPriceLimitX96, bytes data)"

const ABI = [
  "function token0() public view returns (address token)",
  "function token1() public view returns (address token)",
];

module.exports = {
  getUniswapV3Flashloan: async (txEvent) => {
    const flashWithdraws = txEvent.filterFunction(functionSignature);
    const assetSwaps = txEvent.filterFunction(swapAbi);

    const flashloans = await Promise.all(
      flashWithdraws.map(async (withdraw) => {
        const { recipient: flashloanRecipient, amount0, amount1 } = withdraw.args;
        const { address: flashloanAddress } = withdraw;
        let swapRecipient;

        // Get the correct amount and asset address
        const tokenIndex = amount0.gt(ethers.constants.Zero) ? 0 : 1;
        const amount = tokenIndex === 0 ? amount0 : amount1;
        const tokenFnCall = tokenIndex === 0 ? "token0" : "token1";

        const contract = new ethers.Contract(flashloanAddress, ABI, getEthersProvider());
        const asset = await contract[tokenFnCall]();

        if (assetSwaps.length > 0) {
          await Promise.all(assetSwaps.map(async (swap) => {
            const { recipient: swapReceiver, zeroForOne } = swap.args;
            const { address: swapAddress } = swap;

            // Check if there was a `swap` in the same
            // UniswapV3 Pool in the same txn
            if (swapAddress != flashloanAddress) return;

            // Check if the `swap` was swapping OUT of the
            // flashloaned token into the pool's other token
            if ((tokenIndex === 0 && zeroForOne === true) || (tokenIndex === 1 && zeroForOne === false)) {
              swapRecipient = swapReceiver;
            };
          }));
        }

        return {
          asset: asset.toLowerCase(),
          amount,
          account: !swapRecipient ? flashloanRecipient.toLowerCase() : swapRecipient.toLowerCase()
        };
      })
    );

    return flashloans.filter((f) => !!f);
  },
};
const { ethers, getEthersProvider } = require("forta-agent");

const functionSignature = "function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data)";

const ABI = [
  "function token0() public view returns (address token)",
  "function token1() public view returns (address token)",
];

// Also covers PancakeSwap on BSC, as it is a UniswapV2 fork.
module.exports = {
  getUniswapV2Flashloan: async (txEvent) => {
    const swaps = txEvent.filterFunction(functionSignature);

    const flashloans = await Promise.all(
      swaps.map(async (swap) => {
        const { to, data, amount0Out, amount1Out } = swap.args;
        const { address } = swap;

        // https://docs.uniswap.org/protocol/V2/guides/smart-contract-integration/using-flash-swaps
        // If the data length is > 0 than this is a flash swap
        if (data === "0x") {
          return null;
        }

        // Get the correct amount and asset address
        const tokenIndex = amount0Out.gt(ethers.constants.Zero) ? 0 : 1;
        const amount = tokenIndex === 0 ? amount0Out : amount1Out;
        const tokenFnCall = tokenIndex === 0 ? "token0" : "token1";

        const contract = new ethers.Contract(address, ABI, getEthersProvider());
        const asset = await contract[tokenFnCall]();

        return {
          asset: asset.toLowerCase(),
          amount,
          account: to.toLowerCase(),
        };
      })
    );

    return flashloans.filter((f) => !!f);
  },
};

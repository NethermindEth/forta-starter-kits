const { getEthersProvider, ethers } = require("forta-agent");

const functionSignature = "function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data)";
const swapFunctionSelector = "022c0d9f";

const ABI = [
  "function token0() public view returns (address token)",
  "function token1() public view returns (address token)",
];

const EVENT_ABI = [
  "event Swap(address indexed sender, uint256 amount0In, uint256 amount1In, uint256 amount0Out, uint256 amount1Out, address indexed to)",
];

// Also covers PancakeSwap on BSC, as it is a UniswapV2 fork.
module.exports = {
  getUniswapV2Flashloan: async (txEvent) => {
    const swaps = txEvent.filterFunction(functionSignature);

    if (!swaps.length) {
      const calldata = txEvent.transaction.data;
      let index = 0;
      let flashloans = [];

      // Continuously search for the selector within the calldata
      while ((index = calldata.indexOf(swapFunctionSelector, index)) !== -1) {
        // Adjust to start searching for the next occurrence in subsequent iterations
        index += swapFunctionSelector.length;

        // Extract the arguments part of the calldata from the current selector position
        const argsCalldata = "0x" + calldata.substring(index);

        try {
          // NOTE: Will only work when the swap's arguments come right after the function selector in the calldata
          const [amount0Out, amount1Out, to, data] = ethers.utils.defaultAbiCoder.decode(
            ["uint256", "uint256", "address", "bytes"],
            argsCalldata
          );

          if (ethers.utils.hexlify(data) !== "0x") {
            const swapEvents = txEvent.filterLog(EVENT_ABI);

            // Loop through swapEvents to find the corresponding swap event
            for (let i = 0; i < swapEvents.length; i++) {
              const { amount0Out: eventAmount0Out, amount1Out: eventAmount1Out, to: eventTo } = swapEvents[i].args;

              if (
                eventAmount0Out.toString() === amount0Out.toString() &&
                eventAmount1Out.toString() === amount1Out.toString() &&
                to === eventTo
              ) {
                const address = swapEvents[i].address;
                const tokenIndex = amount0Out.gt(ethers.constants.Zero) ? 0 : 1;
                const amount = tokenIndex === 0 ? amount0Out : amount1Out;
                const tokenFnCall = tokenIndex === 0 ? "token0" : "token1";

                const contract = new ethers.Contract(address, ABI, getEthersProvider());
                const asset = await contract[tokenFnCall]();

                flashloans.push({
                  asset: asset.toLowerCase(),
                  amount,
                  account: to.toLowerCase(),
                });
                break;
              }
            }
          }
        } catch {
          break;
        }
      }
      return flashloans;
    } else {
      const flashloans = await Promise.all(
        swaps.map(async (swap, i) => {
          const { data, amount0Out, amount1Out } = swap.args;
          let to;

          // Decoding the `to` field may fail (e.g. tx 0x0f6c2326b49724c586f133857b2586be93ebc3fd5d7559c475180f0800620741 on Mainnet)
          try {
            to = await swap.args.to();
          } catch {
            const swapEvents = txEvent.filterLog(EVENT_ABI);
            if (!swapEvents.length) return null;

            for (let i = 0; i < swapEvents.length; i++) {
              const { amount0Out: eventAmount0Out, amount1Out: eventAmount1Out, to: eventTo } = swapEvents[i].args;
              if (
                eventAmount0Out.toString() === amount0Out.toString() &&
                eventAmount1Out.toString() === amount1Out.toString()
              ) {
                to = eventTo;
                break;
              }
            }
          }

          const { address } = swap;
          // In the context of Uniswap V2's protocol, a non-empty `data` field during a swap operation indicates a flash swap. This is documented in Uniswap's documentation (https://docs.uniswap.org/protocol/V2/guides/smart-contract-integration/using-flash-swaps).
          // However, other protocols with identical swap function signatures may use the `data` field differently. For instance, a transaction on Mainnet (tx: 0xe099c7bb3f1ce6bc79a5df4e66a58d60ce131c1293583a9181a808618933495a) uses `data` to represent a price value.
          // Therefore, to accurately identify flash swaps while accounting for these differences, we check if the `data` field is not only non-empty but also exceeds a certain length threshold. We consider `data` lengths of 64 characters or less (after removing the '0x' prefix) as potentially not indicative of a flash swap.
          if (data === "0x" || data.slice(2).length <= 64) {
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
    }
  },
};

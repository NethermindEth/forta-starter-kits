/* eslint-disable no-plusplus */
const { ethers, getEthersProvider, getTransactionReceipt } = require("forta-agent");
const { MulticallContract, MulticallProvider } = require("forta-agent-tools/lib/utils");
const axios = require("axios").default;

const zero = ethers.constants.Zero;
const ABI = ["function decimals() external view returns (uint8)"];

const ethcallProvider = new MulticallProvider(getEthersProvider());

const tokenDecimals = {};

function getTokenPrice(chain, asset) {
  return `https://api.coingecko.com/api/v3/simple/token_price/${chain}?contract_addresses=${asset}&vs_currencies=usd`;
}

function getNativeTokenPrice(chain) {
  return `https://api.coingecko.com/api/v3/simple/price?ids=${chain}&vs_currencies=usd`;
}

function getChainByChainId(chainId) {
  switch (chainId) {
    case 1:
      return "ethereum";
    case 10:
      return "optimistic-ethereum";
    case 56:
      return "binance-smart-chain";
    case 137:
      return "polygon-pos";
    case 250:
      return "fantom";
    case 42161:
      return "arbitrum-one";
    case 43114:
      return "avalanche";
    default:
      return null;
  }
}

function getNativeTokenByChainId(chainId) {
  switch (chainId) {
    case 1:
      return "ethereum";
    case 10:
      return "ethereum";
    case 56:
      return "binancecoin";
    case 137:
      return "matic-network";
    case 250:
      return "fantom";
    case 42161:
      return "ethereum";
    case 43114:
      return "avalanche-2";
    default:
      return null;
  }
}

module.exports = {
  zero,
  getTransactionReceipt,
  async init() {
    // Init the ethcall Provider and return a chain based on the chainId
    await ethcallProvider.init();
    const { chainId } = await getEthersProvider().getNetwork();
    return {
      chainId,
      chain: getChainByChainId(chainId),
      nativeToken: getNativeTokenByChainId(chainId),
    };
  },
  calculateTokenProfits(events, account) {
    const profits = {};

    events.forEach((event) => {
      const { src: s, dst: d, wad } = event.args;
      const { address } = event;

      // Convert the source and destination addresses to lower case
      const src = s?.toLowerCase();
      const dst = d?.toLowerCase();

      // Set the profit to 0 if it's undefined
      if (!profits[address]) {
        profits[address] = zero;
      }

      if (src === account) {
        profits[address] = profits[address].sub(wad);
      }
      if (dst === account) {
        profits[address] = profits[address].add(wad);
      }
    });

    return profits;
  },
  calculateNativeProfit(traces, account) {
    let nativeProfit = zero;

    traces.forEach((trace) => {
      const { from, to, value, callType, balance, refundAddress } = trace.action;

      let val;

      if (value && value !== "0x0" && callType === "call") {
        // If the trace is a call with non-zero value use the value
        val = ethers.BigNumber.from(value);
      } else if (balance && refundAddress) {
        // If there is a refund address and a balance property use the balance
        val = ethers.BigNumber.from(balance);
        if (refundAddress === account) {
          nativeProfit = nativeProfit.add(val);
        }
      } else {
        return;
      }

      if (from === account) {
        nativeProfit = nativeProfit.sub(val);
      }
      if (to === account) {
        nativeProfit = nativeProfit.add(val);
      }
    });

    return nativeProfit;
  },
  async calculateTokensUsdProfit(tokenProfits, chain) {
    // Remove all zero profits
    const nonZeroProfits = Object.entries(tokenProfits)
      .filter(([, profit]) => !profit.isZero())
      .reduce((obj, [key, value]) => Object.assign(obj, { [key]: value }), {});

    // Get the decimals for all tokens that are not cached
    const newTokens = Object.keys(nonZeroProfits).filter((address) => !tokenDecimals[address]);

    const decimalCalls = newTokens.map((address) => {
      const contract = new MulticallContract(address, ABI);
      return contract.decimals();
    });

    if (decimalCalls.length > 0) {
      const results = await ethcallProvider.all(decimalCalls);

      if (!results[0]) {
        return 0;
      }

      newTokens.forEach((address, index) => {
        tokenDecimals[address] = results[1][index];
      });
    }

    // Calculate the usd profit based on the amount and the price
    const usdTokenProfits = await Promise.all(
      Object.entries(nonZeroProfits).map(async ([address, profit]) => {
        const response = await axios.get(getTokenPrice(chain, address));
        if (!response.data[address]) return 0;

        const usdPrice = response.data[address].usd;

        const tokenAmount = ethers.utils.formatUnits(profit, tokenDecimals[address]);
        return tokenAmount * usdPrice;
      })
    );

    const totalTokensProfit = usdTokenProfits.reduce((sum, profit) => sum + profit, 0);

    return totalTokensProfit;
  },
  async calculateNativeUsdProfit(amount, token) {
    const response = await axios.get(getNativeTokenPrice(token));
    if (!response.data[token]) return 0;

    const usdPrice = response.data[token].usd;

    const tokenAmount = ethers.utils.formatEther(amount);
    return tokenAmount * usdPrice;
  },
  async calculateBorrowedAmount(asset, amount, chain) {
    const response = await axios.get(getTokenPrice(chain, asset));
    const usdPrice = response.data[asset].usd;

    //Setting a high price to avoid false positives as it's a borrowed amount
    if (!response.data[asset]) {
      usdPrice = 1_000_000;
    }

    if (!tokenDecimals[asset]) {
      const contract = new MulticallContract(asset, ABI);
      const results = await ethcallProvider.all([contract.decimals()]);

      if (!results[0]) {
        return ethers.constants.MaxUint256;
      }

      const [decimals] = results[1];

      tokenDecimals[asset] = decimals;
    }

    const tokenAmount = ethers.utils.formatUnits(amount, tokenDecimals[asset]);
    return tokenAmount * usdPrice;
  },
  clear() {
    const tokenAddresses = Object.keys(tokenDecimals);
    const tokensLength = tokenAddresses.length;

    // If the tokenDecimals object has more than 100K elements
    // delete elements until it has 90K
    if (tokensLength > 100_000) {
      for (let i = 0; i < tokensLength - 90_000; i++) {
        delete tokenDecimals[tokenAddresses[i]];
      }
    }
  },
};

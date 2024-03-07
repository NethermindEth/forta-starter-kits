/* eslint-disable no-plusplus */
const { ethers, getEthersProvider, getTransactionReceipt } = require("forta-agent");
const { MulticallContract, MulticallProvider } = require("forta-agent-tools/lib/utils");
const { LRUCache } = require("lru-cache");
const axios = require("axios").default;

const zero = ethers.constants.Zero;
const ABI = ["function decimals() external view returns (uint8)"];

// sDAI on Ethereum mainnet, 0x83F20F44975D03b1b09e64809B757c47f942BEeA,
// does not emit a `Transfer` event when `burn`ing tokens.
// This txn, 0xfeedbf51b4e2338e38171f6e19501327294ab1907ab44cfd2d7e7336c975ace7,
// incorrectly attributed profit in sDAI due to it. Checking for `Withdraw` to
// address that issue.
const peculiarTokens = [
  "0x83f20f44975d03b1b09e64809b757c47f942beea", // sDAI on Ethereum mainnet
];
const peculiarEvents = [
  "Withdraw", // sDAI on Ethereum mainnet
];

const ARB_WETH_ADDRESS = "0x82af49447d8a07e3bd95bd0d56f35241523fbab1";

const etherscanApis = {
  1: {
    urlContractCreation: "https://api.etherscan.io/api?module=contract&action=getcontractcreation",
  },
  10: {
    urlContractCreation: "https://api-optimistic.etherscan.io/api?module=contract&action=getcontractcreation",
  },
  56: {
    urlContractCreation: "https://api.bscscan.com/api?module=contract&action=getcontractcreation",
  },
  137: {
    urlContractCreation: "https://api.polygonscan.com/api?module=contract&action=getcontractcreation",
  },
  250: {
    urlContractCreation: "https://api.ftmscan.com/api?module=contract&action=getcontractcreation",
  },
  42161: {
    urlContractCreation: "https://api.arbiscan.io/api?module=contract&action=getcontractcreation",
  },
  43114: {
    urlContractCreation: "https://api.snowtrace.io/api?module=contract&action=getcontractcreation",
  },
};

const ethcallProvider = new MulticallProvider(getEthersProvider());

const tokenDecimals = {};

const tokensPriceCache = new LRUCache({ max: 100_000 });

let getApiKeys;
const MAX_RETRIES = 3;

// Helps to avoid circular dependency issue
function init() {
  if (!getApiKeys) {
    // Require and set getApiKeys if it hasn't been set
    const agent = require("./agent");
    getApiKeys = agent.getApiKeys;
  }
}

async function getTokenPrice(chain, asset, blockNumber) {
  for (let j = blockNumber - 4; j <= blockNumber; j++) {
    const key = `usdPrice-${asset}-${j}`;
    if (tokensPriceCache.has(key)) {
      const usdPrice = tokensPriceCache.get(key);
      return usdPrice;
    }
  }

  const coinGeckoUrl = `https://api.coingecko.com/api/v3/simple/token_price/${chain}?contract_addresses=${asset}&vs_currencies=usd`;

  const retryCount = 3;
  for (let i = 0; i < retryCount; i++) {
    let response;

    try {
      response = await axios.get(coinGeckoUrl);

      if (response && response.data[asset]) {
        tokensPriceCache.set(`usdPrice-${asset}-${blockNumber}`, response.data[asset].usd);
        return response.data[asset].usd;
      } else {
        throw new Error("Error: Couldn't fetch USD price from CoinGecko");
      }
    } catch {
      const defiLlamaChain = getDefiLlamaTokenChain(chain);
      const defiLlamaUrl = `https://coins.llama.fi/prices/current/${defiLlamaChain}:${asset}`;

      try {
        response = await (await fetch(defiLlamaUrl)).json();
        const price = response.coins[`${defiLlamaChain}:${asset}`].price;

        if (price === null) {
          throw new Error("Error: Couldn't fetch USD price from DeFi Llama");
        } else {
          tokensPriceCache.set(`usdPrice-${asset}-${blockNumber}`, price);
          return price;
        }
      } catch {}
    }

    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  tokensPriceCache.set(`usdPrice-${asset}-${blockNumber}`, 0);
  return 0;
}

async function getNativeTokenPrice(chain, blockNumber) {
  for (let j = blockNumber - 4; j <= blockNumber; j++) {
    const key = `usdPrice-${chain}-${j}`;
    if (tokensPriceCache.has(key)) {
      usdPrice = tokensPriceCache.get(key);
      return usdPrice;
    }
  }

  const coinGeckoUrl = `https://api.coingecko.com/api/v3/simple/price?ids=${chain}&vs_currencies=usd`;

  const retryCount = 3;
  for (let i = 0; i < retryCount; i++) {
    let response;

    try {
      response = await axios.get(coinGeckoUrl);

      if (response && response.data[chain]) {
        tokensPriceCache.set(`usdPrice-${chain}-${blockNumber}`, response.data[chain].usd);
        return response.data[chain].usd;
      } else {
        throw new Error("Error: Couldn't fetch USD price from CoinGecko");
      }
    } catch {
      const defiLlamaChain = getDefiLlamaNativeChain(chain);
      const defiLlamaUrl = `https://coins.llama.fi/prices/current/coingecko:${defiLlamaChain}`;

      try {
        response = await (await fetch(defiLlamaUrl)).json();
        const price = response.coins[`coingecko:${chain}`].price;

        if (price === null) {
          throw new Error("Error: Couldn't fetch USD price from DeFi Llama");
        } else {
          tokensPriceCache.set(`usdPrice-${chain}-${blockNumber}`, price);
          return price;
        }
      } catch {}
    }

    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  tokensPriceCache.set(`usdPrice-${chain}-${blockNumber}`, 0);
  return 0;
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

function getDefiLlamaTokenChain(chain) {
  switch (chain) {
    case "ethereum":
      return "ethereum";
    case "optimistic-ethereum":
      return "optimism";
    case "binance-smart-chain":
      return "bsc";
    case "polygon-pos":
      return "polygon";
    case "fantom":
      return "fantom";
    case "arbitrum-one":
      return "arbitrum";
    case "avalanche":
      return "avax";
    default:
      return null;
  }
}

// Returns the API ID for the requested chains
// native coin, as that is what CoinGecko uses
//
// Note: Returns "Ethereum" for Optimism & Arbitrum
// because that is the native coin of those chains
// (i.e. used to pay for gas)
function getDefiLlamaNativeChain(chain) {
  switch (chain) {
    case "ethereum":
      return "ethereum";
    case "optimistic-ethereum":
      return "ethereum";
    case "binance-smart-chain":
      return "binancecoin";
    case "polygon-pos":
      return "matic-network";
    case "fantom":
      return "fantom";
    case "arbitrum-one":
      return "ethereum";
    case "avalanche":
      return "avalanche-2";
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

function getBlockExplorerKey(chainId) {
  init();
  const apiKeys = getApiKeys();
  const getKey = (keys) => (keys.length > 0 ? keys[Math.floor(Math.random() * keys.length)] : "YourApiKeyToken");

  switch (chainId) {
    case 10:
      return getKey(apiKeys.apiKeys.flashloan.optimisticEtherscanApiKeys);
    case 56:
      return getKey(apiKeys.apiKeys.flashloan.bscscanApiKeys);
    case 137:
      return getKey(apiKeys.apiKeys.flashloan.polygonscanApiKeys);
    case 250:
      return getKey(apiKeys.apiKeys.flashloan.fantomscanApiKeys);
    case 42161:
      return getKey(apiKeys.apiKeys.flashloan.arbiscanApiKeys);
    case 43114:
      return getKey(apiKeys.apiKeys.flashloan.snowtraceApiKeys);
    default:
      return getKey(apiKeys.apiKeys.flashloan.etherscanApiKeys);
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
      const { address } = event;

      // Set the profit to 0 if it's undefined
      if (!profits[address]) {
        profits[address] = zero;
      }

      // Check for general peculiar tokens before checking for specific tokens
      // since both `peculiarTokens` and `perculiarEvents` can grow.
      if (peculiarTokens.includes(address) && peculiarEvents.includes(event.name)) {
        // See note above `peculiarToken` declaration on sDAI on ETH mainnet
        if (address === peculiarTokens[0] && event.name === peculiarEvents[0]) {
          const { owner, shares } = event.args;

          const src = owner?.toLowerCase();

          if (src === account) {
            profits[address] = profits[address].sub(shares);
          }
        }
      } else if (!peculiarEvents.includes(event.name)) {
        const { src: s, dst: d, wad } = event.args;

        // Convert the source and destination addresses to lower case
        const src = s?.toLowerCase();
        const dst = d?.toLowerCase();

        if (src === account) {
          profits[address] = profits[address].sub(wad);
        }
        if (dst === account) {
          profits[address] = profits[address].add(wad);
        }
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
  async calculateTokensUsdProfit(tokenProfits, chain, blockNumber) {
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
        const usdPrice = await getTokenPrice(chain, address, blockNumber);

        if (!usdPrice) return 0;

        const tokenAmount = ethers.utils.formatUnits(profit, tokenDecimals[address]);
        return tokenAmount * usdPrice;
      })
    );

    const totalTokensProfit = usdTokenProfits.reduce((sum, profit) => sum + profit, 0);

    return totalTokensProfit;
  },
  async calculateNativeUsdProfit(amount, token, blockNumber) {
    const usdPrice = await getNativeTokenPrice(token, blockNumber);

    if (!usdPrice) return 0;

    const tokenAmount = ethers.utils.formatEther(amount);
    return tokenAmount * usdPrice;
  },
  async calculateBorrowedAmount(asset, amount, chain) {
    const usdPrice = (await getTokenPrice(chain, asset)) || 1_000_000; // Setting a high price to avoid false positives as it's a borrowed amount

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
  async getContractCreator(address, chainId) {
    const { urlContractCreation } = etherscanApis[chainId];
    const key = getBlockExplorerKey(chainId);
    const url = `${urlContractCreation}&contractaddresses=${address}&apikey=${key}`;

    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
      try {
        const result = await (await fetch(url)).json();

        if (
          result.message.startsWith("NOTOK") ||
          result.message.startsWith("No data") ||
          result.message.startsWith("Query Timeout")
        ) {
          console.log(`Block explorer error occurred (attempt ${attempt}); retrying check for ${address}`);
          if (attempt === MAX_RETRIES) {
            console.log(`Block explorer error occurred (final attempt); skipping check for ${address}`);
            return null;
          }
        } else return result.result[0].contractCreator;
      } catch (error) {
        console.error(`An error occurred during the fetch (attempt ${attempt}):`, error);
        if (attempt === MAX_RETRIES) {
          console.error(`Error during fetch (final attempt); skipping check for ${address}`);
          return null;
        }
      }
    }

    console.error(`Failed to fetch contract creator for ${address} after ${MAX_RETRIES} retries`);
    return null;
  },
  addWethBurnProfitIfApplicable(chainId, transferEvents, calledContract, totalNativeProfit) {
    // Check if we're on Arbitrum and the last Transfer event is a WETH burn from the called contract
    if (Number(chainId) === 42161 && transferEvents[transferEvents.length - 1].address === ARB_WETH_ADDRESS) {
      const { src: s, dst: d, wad } = transferEvents[transferEvents.length - 1].args;
      if (d === ethers.constants.AddressZero && s.toLowerCase() === calledContract.toLowerCase()) {
        // If so, add the profit to the totalNativeProfit
        return totalNativeProfit.add(wad);
      }
    }
    return totalNativeProfit;
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

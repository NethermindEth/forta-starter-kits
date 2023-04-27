const { ethers, getEthersProvider } = require("forta-agent");
const LRU = require("lru-cache");
const AddressType = require("./address-type");
const { moralisApiKeys } = require("./keys");

const USD_VALUE_THRESHOLD = 10000;
const TOTAL_SUPPLY_PERCENTAGE_THRESHOLD = 5;

const TOKEN_ABI = [
  "function balanceOf(address) public view returns (uint256)",
  "function symbol() external view returns (string memory)",
  "function decimals() external view returns (uint8)",
  "function totalSupply() public view returns (uint256)",
];

const MKR_TOKEN_ABI = ["function symbol() external view returns (bytes32)"];

const tokensPriceCache = new LRU({ max: 100_000 });
const decimalsCache = new LRU({ max: 100_000 });
const totalSupplyCache = new LRU({ max: 100_000 });

function hashCode(address, asset) {
  const str = address + asset;
  let hash = 0;
  if (str.length === 0) return hash;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash &= hash; // Convert to 32bit integer
  }
  return hash;
}

async function getAddressType(address, cachedAddresses) {
  if (cachedAddresses.has(address)) {
    return cachedAddresses.get(address);
  }

  const code = await getEthersProvider().getCode(address);
  const type = code === "0x" ? AddressType.Eoa : AddressType.Contract;
  cachedAddresses.set(address, type);
  return type;
}

async function getAssetSymbol(address, cachedAssetSymbols) {
  if (address === "native") return "native";

  if (cachedAssetSymbols.has(address)) {
    return cachedAssetSymbols.get(address);
  }

  let symbol;
  try {
    const contract = new ethers.Contract(address, TOKEN_ABI, getEthersProvider());
    symbol = await contract.symbol();
    cachedAssetSymbols.set(address, symbol);
  } catch {
    try {
      const contract = new ethers.Contract(address, MKR_TOKEN_ABI, getEthersProvider());
      symbol = ethers.utils.parseBytes32String(await contract.symbol());
      cachedAssetSymbols.set(address, symbol);
    } catch {
      symbol = "";
    }
  }

  return symbol;
}

function getNativeTokenByChainId(chainId) {
  switch (Number(chainId)) {
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
      return "ethereum";
  }
}

function getNativeTokenPrice(chain) {
  return `https://api.coingecko.com/api/v3/simple/price?ids=${chain}&vs_currencies=usd`;
}

function getChainByChainId(chainId) {
  switch (Number(chainId)) {
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
      return "ethereum";
  }
}

function getTokenPriceUrl(chain, token) {
  return `https://api.coingecko.com/api/v3/simple/token_price/${chain}?contract_addresses=${token}&vs_currencies=usd`;
}

function getMoralisChainByChainId(chainId) {
  switch (Number(chainId)) {
    case 56:
      return "bsc";
    case 137:
      return "polygon";
    case 250:
      return "fantom";
    case 43114:
      return "avalanche";
    default:
      return "eth";
  }
}

async function getDecimals(block, tokenAddress) {
  const token = new ethers.Contract(tokenAddress, TOKEN_ABI, getEthersProvider());

  const key = `decimals-${tokenAddress}`;
  if (decimalsCache.has(key)) return decimalsCache.get(key);

  const retryCount = 3;
  let decimals = 0;

  for (let i = 0; i <= retryCount; i++) {
    try {
      decimals = await token.decimals({
        blockTag: block,
      });
      decimalsCache.set(key, decimals);
      break;
    } catch (err) {
      if (err instanceof Error) {
        console.log(`Error fetching decimals for token ${tokenAddress}`);
      } else {
        console.log(`Unknown error when fetching total supply: ${err}`);
      }
      if (i === retryCount) {
        decimals = 18;
        console.log(`Failed to fetch decimals for ${tokenAddress} after retries, using default max value: 18`);
        break;
      }

      console.log(`Retrying in 1 second...`);
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }

  return decimals;
}

async function getUniswapPrice(chainId, token) {
  if (!(moralisApiKeys.length > 0)) return 0;
  const moralisApiKey = moralisApiKeys[Math.floor(Math.random() * moralisApiKeys.length)];
  const options = {
    method: "GET",
    params: { chain: getMoralisChainByChainId(chainId) },
    headers: { accept: "application/json", "X-API-Key": moralisApiKey },
  };

  const retryCount = 2;
  for (let i = 0; i <= retryCount; i++) {
    const response = await (await fetch(`https://deep-index.moralis.io/api/v2/erc20/${token}/price`, options)).json();

    if (response.usdPrice) {
      return response.usdPrice;
    } else if (response.message && !response.message.startsWith("No pools found")) {
      await new Promise((resolve) => setTimeout(resolve, 1000));
    } else {
      return 0;
    }
  }
}

async function getValueInUsd(block, chainId, amount, token) {
  let response, usdPrice;
  let foundInCache = false;

  for (let i = block - 9; i <= block; i++) {
    const key = `usdPrice-${token}-${i}`;
    if (tokensPriceCache.has(key)) {
      usdPrice = tokensPriceCache.get(key);
      foundInCache = true;
      break;
    }
  }

  if (!foundInCache) {
    if (token === "native") {
      const chain = getNativeTokenByChainId(chainId);

      let retries = 3;
      while (retries > 0) {
        try {
          response = await (await fetch(getNativeTokenPrice(chain))).json();
          break;
        } catch {
          retries--;
        }
      }
      if (!response || !response[chain]) {
        return 0;
      } else {
        usdPrice = response[chain].usd;
      }
    } else {
      const chain = getChainByChainId(chainId);
      let retryCount = 1;
      for (let i = 0; i < retryCount; i++) {
        try {
          response = await (await fetch(getTokenPriceUrl(chain, token))).json();
          if (response && response[token]) {
            usdPrice = response[token].usd;
            break;
          } else {
            throw new Error("Error: Can't fetch USD price on CoinGecko");
          }
        } catch {
          if (!response) {
            await new Promise((resolve) => setTimeout(resolve, 1000));
          } else {
            break;
          }
        }
      }
      if (!usdPrice) {
        // Moralis API is not available on Optimism
        if (chainId === 10) {
          return 0;
        }
        usdPrice = await getUniswapPrice(chainId, token);
        if (!usdPrice) {
          tokensPriceCache.set(`usdPrice-${token}-${block}`, 0);
          console.log("Setting 0 as the price of token:", token);
          return 0;
        }
      }
    }

    tokensPriceCache.set(`usdPrice-${token}-${block}`, usdPrice);
  }

  let tokenAmount;
  if (token === "native") {
    tokenAmount = ethers.utils.formatEther(amount);
  } else {
    const decimals = await getDecimals(block, token);
    tokenAmount = ethers.utils.formatUnits(amount, decimals);
  }
  return Number(tokenAmount) * usdPrice;
}

async function getTotalSupply(block, tokenAddress) {
  const token = new ethers.Contract(tokenAddress, TOKEN_ABI, getEthersProvider());

  const key = `totalSupply-${tokenAddress}-${block}`;
  if (totalSupplyCache.has(key)) return totalSupplyCache.get(key);

  const retryCount = 3;
  let totalSupply;

  for (let i = 0; i <= retryCount; i++) {
    try {
      totalSupply = await token.totalSupply({
        blockTag: block,
      });
      break;
    } catch (err) {
      if (err instanceof Error) {
        console.log(`Error fetching total supply for token ${tokenAddress}`);
      } else {
        console.log(`Unknown error when fetching total supply: ${err}`);
      }

      if (i === retryCount) {
        totalSupply = ethers.constants.MaxUint256;
        console.log(
          `Failed to fetch total supply for ${tokenAddress} after retries, using default max value ${totalSupply.toString()}`
        );
        break;
      }

      console.log(`Retrying in 1 second...`);
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }

  totalSupplyCache.set(key, totalSupply);

  return totalSupply;
}

module.exports = {
  hashCode,
  getAddressType,
  getAssetSymbol,
  getValueInUsd,
  getTotalSupply,
  TOKEN_ABI,
  USD_VALUE_THRESHOLD,
  TOTAL_SUPPLY_PERCENTAGE_THRESHOLD,
};

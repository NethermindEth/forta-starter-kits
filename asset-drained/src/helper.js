const { ethers, getEthersProvider } = require("forta-agent");
const AddressType = require("./address-type");

const TOKEN_ABI = [
  "function balanceOf(address) public view returns (uint256)",
  "function symbol() external view returns (string memory)",
];

const MKR_TOKEN_ABI = ["function symbol() external view returns (bytes32)"];

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

module.exports = {
  hashCode,
  getAddressType,
  getAssetSymbol,
  TOKEN_ABI,
};

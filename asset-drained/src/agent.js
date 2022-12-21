const { Finding, FindingSeverity, FindingType, ethers, getEthersProvider } = require("forta-agent");
const { MulticallProvider, MulticallContract } = require("forta-agent-tools");
const LRU = require("lru-cache");

const { getBlocksIn10Minutes, hashCode, getAddressType, getAssetSymbol, TOKEN_ABI } = require("./helper");
const AddressType = require("./address-type");

const ZERO = ethers.constants.Zero;
const ERC20_TRANSFER_EVENT = "event Transfer(address indexed from, address indexed to, uint256 value)";

const ethcallProvider = new MulticallProvider(getEthersProvider());

const cachedAddresses = new LRU({ max: 100_000 });
const cachedAssetSymbols = new LRU({ max: 100_000 });

let blocksIn10Minutes;
let transfersObj = {};

const initialize = async () => {
  const { chainId } = await getEthersProvider().getNetwork();
  blocksIn10Minutes = getBlocksIn10Minutes(chainId);
  await ethcallProvider.init();
};

const handleTransaction = async (txEvent) => {
  const { hash, from: txFrom, blockNumber } = txEvent;
  txEvent
    .filterLog(ERC20_TRANSFER_EVENT)
    .filter((event) => !event.args.value.eq(ZERO))
    .filter((event) => event.address !== event.args.from.toLowerCase())
    .forEach((event) => {
      const asset = event.address;
      const { from, to, value } = event.args;
      const hashFrom = hashCode(from, asset);
      const hashTo = hashCode(to, asset);

      if (!transfersObj[hashFrom]) {
        transfersObj[hashFrom] = {
          asset,
          address: from,
          value: ZERO,
          blockNumber,
          txs: {},
        };
      }
      if (!transfersObj[hashTo]) {
        transfersObj[hashTo] = {
          asset,
          address: to,
          value: ZERO,
          blockNumber,
          txs: {},
        };
      }

      transfersObj[hashFrom].value = transfersObj[hashFrom].value.sub(value);

      if (!transfersObj[hashFrom].txs[to]) {
        transfersObj[hashFrom].txs[to] = [{ hash, txFrom }];
      } else {
        transfersObj[hashFrom].txs[to].push({ hash, txFrom });
      }

      transfersObj[hashTo].value = transfersObj[hashTo].value.add(value);
    });

  txEvent.traces.forEach((trace) => {
    const { from, to, value, callType } = trace.action;

    if (value && value !== "0x0" && callType === "call") {
      const hashFrom = hashCode(from, "native");
      const hashTo = hashCode(to, "native");

      if (!transfersObj[hashFrom]) {
        transfersObj[hashFrom] = {
          asset: "native",
          address: from,
          value: ZERO,
          blockNumber,
          txs: {},
        };
      }

      if (!transfersObj[hashTo]) {
        transfersObj[hashTo] = {
          asset: "native",
          address: to,
          value: ZERO,
          blockNumber,
          txs: {},
        };
      }

      transfersObj[hashFrom].value = transfersObj[hashFrom].value.sub(value);

      if (!transfersObj[hashFrom].txs[to]) {
        transfersObj[hashFrom].txs[to] = [{ hash, txFrom }];
      } else {
        transfersObj[hashFrom].txs[to].push({ hash, txFrom });
      }

      transfersObj[hashTo].value = transfersObj[hashTo].value.add(value);
    }
  });

  return [];
};

const handleBlock = async (blockEvent) => {
  const { blockNumber } = blockEvent;
  const findings = [];

  // Only process addresses that had more funds withdrawn than deposited
  let transfers = Object.values(transfersObj)
    .filter((t) => t.value.lt(ZERO))
    .filter((t) => t.address !== ethers.constants.AddressZero);
  if (transfers.length === 0) return [];

  const st = new Date();
  console.log(`processing block ${blockNumber}`);

  const balanceCalls = transfers.map((e) => {
    if (e.asset === "native") {
      return ethcallProvider.getEthBalance(e.address);
    }

    const contract = new MulticallContract(e.asset, TOKEN_ABI);
    return contract.balanceOf(e.address);
  });

  // Only process addresses with fully drained assets
  const balances = await ethcallProvider.tryAll(balanceCalls, blockNumber - 1);
  transfers = transfers.filter((_, i) => balances[i]["success"] && balances[i]["returnData"].eq(ZERO));

  // Filter out events to EOAs
  transfers = await Promise.all(
    transfers.map(async (event) => {
      const type = await getAddressType(event.address, cachedAddresses);
      return type === AddressType.Contract ? event : null;
    })
  );
  transfers = transfers.filter((e) => !!e);

  const calls = await Promise.all([
    ...transfers.map((event) => getAssetSymbol(event.asset, cachedAssetSymbols)),
    ...transfers.map(async (event) => {
      const block10MinsAgo = blockNumber - blocksIn10Minutes;

      if (event.asset === "native") {
        return getEthersProvider().getBalance(event.address, block10MinsAgo);
      }

      const contract = new ethers.Contract(event.asset, TOKEN_ABI, getEthersProvider());
      let output;
      try {
        output = await contract.balanceOf(event.address, {
          blockTag: block10MinsAgo,
        });
      } catch {
        output = ethers.BigNumber.from(0);
      }
      return output;
    }),
  ]);

  const symbols = calls.slice(0, transfers.length);
  const balances10MinsAgo = calls.slice(transfers.length);

  symbols.forEach((s, i) => {
    transfers[i].symbol = s;
  });

  transfers = transfers.filter((t, i) => {
    // Flag the address as ignored if its balance was 0 10 minutes ago
    if (balances10MinsAgo[i].eq(ZERO)) {
      cachedAddresses.set(t.address, AddressType.Ignored);
      return false;
    }
    return true;
  });

  transfers.forEach((t) => {
    findings.push(
      Finding.fromObject({
        name: "Asset drained",
        description: `All ${t.symbol} tokens were drained from ${t.address}`,
        alertId: "ASSET-DRAINED",
        severity: FindingSeverity.High,
        type: FindingType.Exploit,
        metadata: {
          contract: t.address,
          asset: t.asset,
          initiators: [
            ...new Set(
              Object.values(t.txs)
                .flat()
                .map((tx) => tx.txFrom)
            ),
          ],
          txHashes: [
            ...new Set(
              Object.values(t.txs)
                .flat()
                .map((tx) => tx.hash)
            ),
          ],
          blockNumber: t.blockNumber,
        },
        addresses: [...new Set(Object.keys(t.txs))],
      })
    );
  });

  const et = new Date();
  console.log(`previous block processed in ${et - st}ms`);
  transfersObj = {};
  return findings;
};

module.exports = {
  initialize,
  handleTransaction,
  handleBlock,
  getTransfersObj: () => transfersObj, // Exported for unit tests
};

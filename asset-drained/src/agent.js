const { Finding, FindingSeverity, FindingType, ethers, getEthersProvider, Label, EntityType } = require("forta-agent");
const { MulticallProvider, MulticallContract } = require("forta-agent-tools");
const LRU = require("lru-cache");

const { hashCode, getAddressType, getAssetSymbol, TOKEN_ABI } = require("./helper");
const AddressType = require("./address-type");
const { PersistenceHelper } = require("./persistence.helper");

const ZERO = ethers.constants.Zero;
const ERC20_TRANSFER_EVENT = "event Transfer(address indexed from, address indexed to, uint256 value)";

const DATABASE_URL = "https://research.forta.network/database/bot/";

let chainId;

const ASSET_DRAINED_TXN_KEY = "nm-asset-drained-bot-key";
const ALL_TRANSFERS_KEY = "nm-all-transfers-bot-key";

let assetDrainedTransactions = 0;
let totalTransferTransactions = 0;

const ethcallProvider = new MulticallProvider(getEthersProvider());

const cachedAddresses = new LRU({ max: 100_000 });
const cachedAssetSymbols = new LRU({ max: 100_000 });

let transfersObj = {};

const provideInitialize = (provider, persistenceHelper, assetDrainedTxnKey, allTransfersKey) => {
  return async () => {
    await ethcallProvider.init();

    chainId = (await provider.getNetwork()).chainId.toString();
    assetDrainedTransactions = await persistenceHelper.load(
      assetDrainedTransactions,
      assetDrainedTxnKey.concat("-", chainId)
    );
    totalTransferTransactions = await persistenceHelper.load(
      totalTransferTransactions,
      allTransfersKey.concat("-", chainId)
    );
  };
};

const provideHandleTransaction = () => {
  return async (txEvent) => {
    const { hash, from: txFrom, blockNumber } = txEvent;
    txEvent
      .filterLog(ERC20_TRANSFER_EVENT)
      .filter((event) => !event.args.value.eq(ZERO))
      .filter((event) => event.address !== event.args.from.toLowerCase())
      .forEach((event) => {
        totalTransferTransactions += 1;
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
};

const provideHandleBlock = (persistenceHelper, assetDrainedTxnKey, allTransfersKey) => {
  return async (blockEvent) => {
    const { blockNumber } = blockEvent;
    const findings = [];

    if (blockEvent.blockNumber % 240 === 0) {
      await persistenceHelper.persist(assetDrainedTransactions, assetDrainedTxnKey.concat("-", chainId));
      await persistenceHelper.persist(totalTransferTransactions, allTransfersKey.concat("-", chainId));
    }

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

    // Get the balances of the addresses pre- and post-drain
    const balancesPreDrain = await ethcallProvider.tryAll(balanceCalls, blockNumber - 2);
    const balancesPostDrain = await ethcallProvider.tryAll(balanceCalls, blockNumber - 1);

    // Filter for transfers where the victim's post-drain balance
    // is 1% or less of their pre-drain balance
    transfers = transfers.filter(
      (_, i) =>
        balancesPostDrain[i]["success"] &&
        balancesPreDrain[i]["success"] &&
        // Balance check: less than or equal to 1% of pre drain balance
        balancesPostDrain[i]["returnData"].lte(balancesPreDrain[i]["returnData"].div(100))
    );

    // Filter out events to EOAs
    transfers = await Promise.all(
      transfers.map(async (event) => {
        const type = await getAddressType(event.address, cachedAddresses);
        return type === AddressType.Contract ? event : null;
      })
    );
    transfers = transfers.filter((e) => !!e);
    assetDrainedTransactions += transfers.length;

    const symbols = await Promise.all([...transfers.map((event) => getAssetSymbol(event.asset, cachedAssetSymbols))]);

    symbols.forEach((s, i) => {
      transfers[i].symbol = s;
    });

    const anomalyScore = assetDrainedTransactions / totalTransferTransactions;
    transfers.forEach((t) => {
      findings.push(
        Finding.fromObject({
          name: "Asset drained",
          description: `99% or more of ${t.address}'s ${t.symbol} tokens were drained`,
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
            anomalyScore: anomalyScore.toFixed(2),
          },
          labels: [
            Label.fromObject({
              entityType: EntityType.Address,
              entity: t.address,
              label: "Asset Drained Victim",
              confidence: 1,
            }),
            Label.fromObject({
              entityType: EntityType.Block,
              entity: blockNumber - 1,
              label: "Asset Drained Block",
              confidence: 1,
            }),
          ],
          addresses: [...new Set(Object.keys(t.txs))],
        })
      );
    });

    const et = new Date();
    console.log(`previous block processed in ${et - st}ms`);
    transfersObj = {};
    return findings;
  };
};

module.exports = {
  initialize: provideInitialize(
    getEthersProvider(),
    new PersistenceHelper(DATABASE_URL),
    ASSET_DRAINED_TXN_KEY,
    ALL_TRANSFERS_KEY
  ),
  provideInitialize,
  handleTransaction: provideHandleTransaction(),
  provideHandleTransaction,
  handleBlock: provideHandleBlock(new PersistenceHelper(DATABASE_URL), ASSET_DRAINED_TXN_KEY, ALL_TRANSFERS_KEY),
  provideHandleBlock,
  getTransfersObj: () => transfersObj, // Exported for unit tests
};

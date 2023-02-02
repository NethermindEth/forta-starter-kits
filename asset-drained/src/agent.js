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
    assetDrainedTransactions = await persistenceHelper.load(assetDrainedTxnKey.concat("-", chainId));
    totalTransferTransactions = await persistenceHelper.load(allTransfersKey.concat("-", chainId));
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
  let cachedFindings = [];
  return async (blockEvent) => {
    const { blockNumber } = blockEvent;
    const findings = [];

    if (cachedFindings.length >= 10) {
      cachedFindings.splice(0, 10);
    } else {
      cachedFindings = [];
    }

    // Only process addresses that had more funds withdrawn than deposited
    let transfers = Object.values(transfersObj)
      .filter((t) => t.value.lt(ZERO))
      .filter((t) => t.address !== ethers.constants.AddressZero)
      .filter((t) => t.blockNumber === blockNumber - 1);
    // If there are no transfers, but still a block in which the bot
    // should persist the values, push the values to the database
    // despite there being no transfers
    if (transfers.length === 0 && blockEvent.blockNumber % 240 === 0) {
      await persistenceHelper.persist(assetDrainedTransactions, assetDrainedTxnKey.concat("-", chainId));
      await persistenceHelper.persist(totalTransferTransactions, allTransfersKey.concat("-", chainId));
      return [];
    } else if (transfers.length === 0) {
      return [];
    }

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
    let balances = [];

    transfers = transfers.filter((_, i) => {
      if (
        balancesPostDrain[i]["success"] &&
        balancesPreDrain[i]["success"] &&
        // Balance check: less than 1% of pre drain balance
        ethers.BigNumber.from(balancesPostDrain[i]["returnData"]).lt(
          ethers.BigNumber.from(balancesPreDrain[i]["returnData"].div(100))
        )
      ) {
        balances.push([balancesPreDrain[i]["returnData"].toString(), balancesPostDrain[i]["returnData"].toString()]);
        return true;
      } else if (!balancesPostDrain[i]["success"]) {
        console.log(
          "Failed to get balance for address",
          transfers[i].address,
          "on block",
          blockNumber - 1,
          "balances:",
          balancesPostDrain[i]
        );
        console.log(transfers[i]);
      } else if (!balancesPreDrain[i]["success"]) {
        console.log(
          "Failed to get balance for address",
          transfers[i].address,
          "on block",
          blockNumber - 2,
          "balances:",
          balancesPreDrain[i]
        );
      }
      return false;
    });

    // Filter out events to EOAs
    transfers = await Promise.all(
      transfers.map(async (event, i) => {
        const type = await getAddressType(event.address, cachedAddresses);
        if (type === AddressType.Contract) {
          return event;
        } else {
          balances[i] = null;
          return null;
        }
      })
    );
    transfers = transfers.filter((e) => !!e);
    balances = balances.filter((e) => !!e);
    assetDrainedTransactions += transfers.length;

    const symbols = await Promise.all([...transfers.map((event) => getAssetSymbol(event.asset, cachedAssetSymbols))]);

    symbols.forEach((s, i) => {
      transfers[i].symbol = s;
    });

    const anomalyScore = assetDrainedTransactions / totalTransferTransactions;
    transfers.forEach((t, i) => {
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
            preDrainBalance: balances[i][0],
            postDrainBalance: balances[i][1],
            txHashes: [
              ...new Set(
                Object.values(t.txs)
                  .flat()
                  .map((tx) => tx.hash)
              ),
            ],
            blockNumber: t.blockNumber,
            anomalyScore: anomalyScore.toFixed(2) === "0.00" ? anomalyScore.toString() : anomalyScore.toFixed(2),
          },
          labels: [
            Label.fromObject({
              entityType: EntityType.Address,
              entity: t.address,
              label: "victim",
              confidence: 1,
            }),
            Label.fromObject({
              entityType: EntityType.Block,
              entity: blockNumber - 1,
              label: "block",
              confidence: 1,
            }),
          ],
          addresses: [...new Set(Object.keys(t.txs))],
        })
      );
    });

    // Persist values here if there were transfers
    // to futher process (This will have the updated
    // `assetDrainedTransactions` that were incremented)
    if (blockEvent.blockNumber % 240 === 0) {
      await persistenceHelper.persist(assetDrainedTransactions, assetDrainedTxnKey.concat("-", chainId));
      await persistenceHelper.persist(totalTransferTransactions, allTransfersKey.concat("-", chainId));
    }

    cachedFindings.push(...findings);

    const et = new Date();
    console.log(`previous block processed in ${et - st}ms`);
    transfersObj = {};
    return cachedFindings.slice(0, 10);
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

const { Finding, FindingSeverity, FindingType, ethers, getEthersProvider, Label, EntityType } = require("forta-agent");
const { MulticallProvider, MulticallContract } = require("forta-agent-tools");
const LRU = require("lru-cache");
const { default: calculateAlertRate } = require("bot-alert-rate");
const { ScanCountType } = require("bot-alert-rate");
const { getSecrets } = require("./storage");

const {
  hashCode,
  getAddressType,
  getAssetSymbol,
  getValueInUsd,
  TOKEN_ABI,
  getTotalSupply,
  USD_VALUE_THRESHOLD,
} = require("./helper");
const AddressType = require("./address-type");

const ZERO = ethers.constants.Zero;
const ERC20_TRANSFER_EVENT = "event Transfer(address indexed from, address indexed to, uint256 value)";
const REMOVE_LIQUIDITY_EVENTS = [
  "event Burn(address indexed sender, uint amount0, uint amount1, address indexed to)",
  "event RemoveLiquidityOne(address indexed provider, uint256 token_amount, uint256 coin_amount, uint256 token_supply)",
  "event RemoveLiquidity(address indexed provider, uint256[4] token_amounts, uint256[4] fees, uint256 token_supply)",
];

let chainId;
let isRelevantChain;
let apiKeys;
let transfersCount = 0;
let liqRemovalTransfersCount = 0;
const BOT_ID = "0xe4a8660b5d79c0c64ac6bfd3b9871b77c98eaaa464aa555c00635e9d8b33f77f";

const ethcallProvider = new MulticallProvider(getEthersProvider());

const cachedAddresses = new LRU({ max: 100_000 });
const cachedAssetSymbols = new LRU({ max: 100_000 });

let transfersObj = {};
let burnEventsArray = [];

const provideInitialize = (provider) => {
  return async () => {
    await ethcallProvider.init();
    apiKeys = await getSecrets();
    process.env["ZETTABLOCK_API_KEY"] = apiKeys.generalApiKeys.ZETTABLOCK[1];
    chainId = (await provider.getNetwork()).chainId.toString();

    //  Optimism, Fantom & Avalanche not yet supported by bot-alert-rate package
    isRelevantChain = [10, 250, 43114].includes(Number(chainId));
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

    if (txEvent.filterLog(REMOVE_LIQUIDITY_EVENTS).length) {
      burnEventsArray.push(txEvent.hash);
    }

    return [];
  };
};

const provideHandleBlock = (calculateAlertRate, getValueInUsd, getTotalSupply) => {
  return async (blockEvent) => {
    const { blockNumber } = blockEvent;
    const findings = [];

    const st = new Date();
    console.log(`processing block ${blockNumber}`);

    // Only process addresses that had more funds withdrawn than deposited
    let transfers = Object.values(transfersObj)
      .filter((t) => t.value.lt(ZERO))
      .filter((t) => t.address !== ethers.constants.AddressZero)
      .filter((t) =>
        [56, 137].includes(Number(chainId))
          ? t.blockNumber === blockNumber - 4
          : [1, 250].includes(Number(chainId))
          ? t.blockNumber === blockNumber - 2
          : t.blockNumber === blockNumber - 1
      );

    if (!transfers.length) return findings;

    const balanceCalls = transfers.map((e) => {
      if (e.asset === "native") {
        return ethcallProvider.getEthBalance(e.address);
      }

      const contract = new MulticallContract(e.asset, TOKEN_ABI);
      return contract.balanceOf(e.address);
    });

    // Get the balances of the addresses pre- and post-drain
    const balancesPreDrain = await ethcallProvider.tryAll(
      balanceCalls,
      [56, 137].includes(Number(chainId))
        ? blockNumber - 5
        : [1, 250].includes(Number(chainId))
        ? blockNumber - 3
        : blockNumber - 2,
      balanceCalls.length // One batch
    );

    const balancesPostDrain = await ethcallProvider.tryAll(
      balanceCalls,
      [56, 137].includes(Number(chainId))
        ? blockNumber - 4
        : [1, 250].includes(Number(chainId))
        ? blockNumber - 2
        : blockNumber - 1,
      balanceCalls.length // One batch
    );

    if (balancesPreDrain.length !== balancesPostDrain.length) {
      return findings;
    }

    let balances = [];

    // Filter for transfers where the victim's post-drain balance
    // is less than 1% of their pre-drain balance
    transfers = transfers.filter((_, i) => {
      if (
        balancesPostDrain[i]["success"] &&
        balancesPreDrain[i]["success"] &&
        // Balance check: less than 1% of pre drain balance
        ethers.BigNumber.from(balancesPostDrain[i]["returnData"]).lt(
          ethers.BigNumber.from(balancesPreDrain[i]["returnData"].div(100))
        )
      ) {
        balances.push([balancesPreDrain[i]["returnData"], balancesPostDrain[i]["returnData"]]);
        return true;
      } else if (!balancesPostDrain[i]["success"]) {
        console.log(
          "Failed to get balance for address",
          transfers[i].address,
          "on block",
          [56, 137].includes(Number(chainId))
            ? blockNumber - 4
            : [1, 250].includes(Number(chainId))
            ? blockNumber - 2
            : blockNumber - 1,
          "balances:",
          balancesPostDrain[i].toString()
        );
      } else if (!balancesPreDrain[i]["success"]) {
        console.log(
          "Failed to get balance for address",
          transfers[i].address,
          "on block",
          [56, 137].includes(Number(chainId))
            ? blockNumber - 5
            : [1, 250].includes(Number(chainId))
            ? blockNumber - 3
            : blockNumber - 2,
          "balances:",
          balancesPreDrain[i].toString()
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

    const symbols = await Promise.all([...transfers.map((event) => getAssetSymbol(event.asset, cachedAssetSymbols))]);

    symbols.forEach((s, i) => {
      transfers[i].symbol = s;
    });

    // Filter out test tokens
    transfers = transfers.filter((t) => t.symbol.toLowerCase() !== "test");

    const filteredTransfersAndBalances = await transfers.reduce(async (accPromise, transfer, i) => {
      const acc = await accPromise;
      const amountLost = balances[i][0].sub(balances[i][1]);
      const value = await getValueInUsd(
        blockNumber,
        chainId,
        amountLost.toString(),
        transfer.asset,
        apiKeys.generalApiKeys.MORALIS
      );
      let shouldInclude = false;

      if (value > USD_VALUE_THRESHOLD) {
        shouldInclude = true;
      } else if (value === 0 && transfer.asset !== "native") {
        const totalSupply = await getTotalSupply(blockNumber, transfer.asset);
        const threshold = totalSupply.div(20); // 5% of total supply
        if (amountLost.gt(threshold)) {
          shouldInclude = true;
        }
      }

      if (shouldInclude) {
        acc.filteredTransfers.push(transfer);
        acc.filteredBalances.push(balances[i]);
      }

      return acc;
    }, Promise.resolve({ filteredTransfers: [], filteredBalances: [] }));

    const { filteredTransfers, filteredBalances } = filteredTransfersAndBalances;

    await Promise.all(
      filteredTransfers.map(async (t, i) => {
        const txsHashes = Object.values(t.txs)
          .flat()
          .map((tx) => tx.hash);

        // check if any of the txsHashes is in burnEventsArray
        txsHashes.forEach((txHash) => {
          if (burnEventsArray.includes(txHash)) {
            t.isBurn = true;
          }
        });

        const initiators = [
          ...new Set(
            Object.values(t.txs)
              .flat()
              .map((tx) => tx.txFrom)
          ),
        ];

        const attackerLabels = initiators.map((txFrom) =>
          Label.fromObject({
            entityType: EntityType.Address,
            entity: txFrom,
            label: "Attacker",
            confidence: 0.5,
          })
        );

        // check if the tx is liquidity removal
        let anomalyScore;
        let alertId;

        if (t.isBurn) {
          if (isRelevantChain) liqRemovalTransfersCount++;
          alertId = "ASSET-DRAINED-LIQUIDITY-REMOVAL";

          anomalyScore = await calculateAlertRate(
            Number(chainId),
            BOT_ID,
            alertId,
            isRelevantChain ? ScanCountType.CustomScanCount : ScanCountType.TransferCount,
            liqRemovalTransfersCount // No issue in passing 0 for non-relevant chains
          );
        } else {
          if (isRelevantChain) transfersCount++;
          alertId = "ASSET-DRAINED";

          anomalyScore = await calculateAlertRate(
            Number(chainId),
            BOT_ID,
            alertId,
            isRelevantChain ? ScanCountType.CustomScanCount : ScanCountType.TransferCount,
            transfersCount // No issue in passing 0 for non-relevant chains
          );
        }

        findings.push(
          Finding.fromObject({
            name: "Asset drained",
            description: `99% or more of ${t.address}'s ${t.symbol} tokens were drained`,
            alertId: alertId,
            severity: FindingSeverity.High,
            type: FindingType.Exploit,
            metadata: {
              contract: t.address,
              asset: t.asset,
              initiators,
              preDrainBalance: filteredBalances[i][0].toString(),
              postDrainBalance: filteredBalances[i][1].toString(),
              txHashes: [
                ...new Set(
                  Object.values(t.txs)
                    .flat()
                    .map((tx) => tx.hash)
                ),
              ],
              blockNumber: t.blockNumber,
              anomalyScore: anomalyScore.toString(),
            },
            labels: [
              Label.fromObject({
                entityType: EntityType.Address,
                entity: t.address,
                label: "Victim",
                confidence: 1,
              }),
              ...attackerLabels,
            ],
            addresses: [...new Set(Object.keys(t.txs))],
          })
        );
      })
    );

    const et = new Date();
    console.log(`previous block processed in ${et - st}ms`);
    transfersObj = {};
    burnEventsArray = [];
    return findings;
  };
};

module.exports = {
  initialize: provideInitialize(getEthersProvider()),
  provideInitialize,
  handleTransaction: provideHandleTransaction(),
  provideHandleTransaction,
  handleBlock: provideHandleBlock(calculateAlertRate, getValueInUsd, getTotalSupply),
  provideHandleBlock,
  getTransfersObj: () => transfersObj, // Exported for unit tests
};

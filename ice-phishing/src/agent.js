const { ethers, getEthersProvider } = require("forta-agent");
const LRU = require("lru-cache");
const { default: axios } = require("axios");
const { default: calculateAlertRate } = require("bot-alert-rate");
const { ZETTABLOCK_API_KEY } = require("./keys");
const { openseaHandleTransaction } = require("./opensea.alert");
const { sweepTokenHandleTransaction } = require("./sweepToken.alert");
const { permitsHandleTransaction } = require("./permits.alerts");
const { approvalsHandleTransaction } = require("./approvals.alerts");
const { transfersHandletransaction } = require("./transfers.alerts");
const { getSuspiciousContracts, getTransactions, checkObjectSizeAndCleanup, cleanData } = require("./helper");
const {
  TIME_PERIOD,
  permitFunctionABI,
  daiPermitFunctionABI,
  uniswapPermitFunctionABI,
  approvalEventErc20ABI,
  approvalEventErc721ABI,
  approvalForAllEventABI,
  transferEventErc20ABI,
  transferEventErc721ABI,
  erc1155transferEventABI,
  MAX_OBJECT_SIZE,
} = require("./utils");
const { PersistenceHelper } = require("./persistence.helper");

let scamAddresses = [];

// Every address is ~100B
// 100_000 addresses are 10MB
const cachedAddresses = new LRU({ max: 100_000 });

const cachedERC1155Tokens = new LRU({ max: 100_000 });

let chainId;
let isRelevantChain;
let transactionsProcessed = 0;
let lastBlock = 0;
let scamSnifferDB = {
  data: {},
};

const DATABASE_URL = "https://research.forta.network/database/bot/";

const DATABASE_OBJECT_KEY = {
  key: "nm-icephishing-bot-objects-v6-shard",
};

let objects = {
  approvals: {},
  approvalsERC20: {},
  approvalsERC721: {},
  approvalsForAll721: {},
  approvalsForAll1155: {},
  approvalsInfoSeverity: {},
  approvalsERC20InfoSeverity: {},
  approvalsERC721InfoSeverity: {},
  approvalsForAll721InfoSeverity: {},
  approvalsForAll1155InfoSeverity: {},
  permissions: {},
  permissionsInfoSeverity: {},
  transfers: {},
  transfersLowSeverity: {},
  pigButcheringTransfers: {},
};

const DATABASE_KEYS = {
  totalUpgrades: "nm-icephishing-bot-total-upgrades-key",
  totalPermits: "nm-icephishing-bot-total-permits-key",
  totalApprovals: "nm-icephishing-bot-total-approvals-key",
  totalTransfers: "nm-icephishing-bot-total-transfers-key",
  totalERC20Approvals: "nm-icephishing-bot-total-erc20-approvals-key",
  totalERC721Approvals: "nm-icephishing-bot-total-erc721-approvals-key",
  totalERC721ApprovalsForAll: "nm-icephishing-bot-total-erc721-approvalsforall-key",
  totalERC1155ApprovalsForAll: "nm-icephishing-bot-total-erc1155-approvalsforall-key",
};

const counters = {
  totalUpgrades: 0,
  totalPermits: 0,
  totalApprovals: 0,
  totalTransfers: 0,
  totalERC20Approvals: 0,
  totalERC721Approvals: 0,
  totalERC721ApprovalsForAll: 0,
  totalERC1155ApprovalsForAll: 0,
};

const provideInitialize = (provider, persistenceHelper, databaseKeys, counters, databaseObjectsKey) => {
  return async () => {
    ({ chainId } = await provider.getNetwork());
    process.env["ZETTABLOCK_API_KEY"] = ZETTABLOCK_API_KEY;

    //  Optimism, Fantom & Avalanche not yet supported by bot-alert-rate package
    isRelevantChain = [10, 250, 43114].includes(Number(chainId));

    Object.keys(databaseKeys).forEach((key) => {
      databaseKeys[key] = `${databaseKeys[key]}-${chainId}`;
    });

    for (const key in counters) {
      counters[key] = await persistenceHelper.load(databaseKeys[key]);
    }

    databaseObjectsKey.key = `${databaseObjectsKey.key}-${chainId}`;

    objects = await persistenceHelper.load(databaseObjectsKey.key);
  };
};

let transactions = [];

const provideHandleTransaction =
  (provider, counters, databaseObjectsKey, persistenceHelper, objects, calculateAlertRate, lastBlock) =>
  async (txEvent) => {
    const findings = [];
    const { hash, blockNumber, from: f } = txEvent;

    if (blockNumber != lastBlock) {
      objects = await persistenceHelper.load(databaseObjectsKey.key);
      if (blockNumber % 240 == 0 || lastBlock === 0) {
        scamSnifferDB = await axios.get(
          "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/combined.json"
        );
      }

      transactions = await getTransactions(provider, blockNumber);

      if (!chainId) {
        ({ chainId } = transactions[0]);
        Object.keys(DATABASE_KEYS).forEach((key) => {
          DATABASE_KEYS[key] = `${DATABASE_KEYS[key]}-${chainId}`;
        });
        databaseObjectsKey.key = `${databaseObjectsKey.key}-${chainId}`;
      }

      const objectsSize = Buffer.from(JSON.stringify(objects)).length;
      console.log("Objects Size:", objectsSize);

      if (objectsSize > MAX_OBJECT_SIZE) {
        Object.values(objects).forEach((obj) => checkObjectSizeAndCleanup(obj));
        console.log("Objects Size After Cleanup:", Buffer.from(JSON.stringify(objects)).length);
      }

      console.log("Approvals Size:", Buffer.from(JSON.stringify(objects.approvals)).length);
      console.log("Approvals ERC20 Size:", Buffer.from(JSON.stringify(objects.approvalsERC20)).length);
      console.log("Approvals ERC721 Size:", Buffer.from(JSON.stringify(objects.approvalsERC721)).length);
      console.log("Transfers Size:", Buffer.from(JSON.stringify(objects.transfers)).length);
      console.log("Approvals Info Size:", Buffer.from(JSON.stringify(objects.approvalsInfoSeverity)).length);
      console.log("Approvals ERC20 Info Size:", Buffer.from(JSON.stringify(objects.approvalsERC20InfoSeverity)).length);
      console.log(
        "Approvals ERC721 Info Size:",
        Buffer.from(JSON.stringify(objects.approvalsERC721InfoSeverity)).length
      );
      console.log("Transfers Low Size:", Buffer.from(JSON.stringify(objects.transfersLowSeverity)).length);
      console.log("Approvals For All ERC721 size:", Buffer.from(JSON.stringify(objects.approvalsForAll721)).length);
      console.log("Approvals For All ERC1155 size:", Buffer.from(JSON.stringify(objects.approvalsForAll1155)).length);
      console.log(
        "Approvals For All ERC721 Info size:",
        Buffer.from(JSON.stringify(objects.approvalsForAll721InfoSeverity)).length
      );
      console.log(
        "Approvals For All ERC1155 Info size:",
        Buffer.from(JSON.stringify(objects.approvalsForAll1155InfoSeverity)).length
      );
      console.log("Permits Size:", Buffer.from(JSON.stringify(objects.permissions)).length);
      console.log("Permits Info Size:", Buffer.from(JSON.stringify(objects.permissionsInfoSeverity)).length);
      console.log("Pig Butchering Transfers Size:", Buffer.from(JSON.stringify(objects.pigButcheringTransfers)).length);

      lastBlock = blockNumber;
      console.log(`-----Transactions processed in block ${blockNumber - 3}: ${transactionsProcessed}-----`);
      transactionsProcessed = 0;
    }
    transactionsProcessed += 1;

    const st1 = new Date().getTime();
    if (hash === transactions[transactions.length - 1].hash) {
      // Load the existing object from the database
      const persistedObj = await persistenceHelper.load(databaseObjectsKey.key);

      // Merge the persisted object with the new object
      const mergedObj = {
        ...objects,
        ...persistedObj,
      };

      // Iterate through the keys of the objects
      for (const key of Object.keys(objects)) {
        const subObj = objects[key];

        // Check if the sub-object has any keys
        if (Object.keys(subObj).length > 0) {
          const persistedSubObj = persistedObj[key] || {};
          const mergedSubObj = {
            ...subObj,
            ...persistedSubObj,
          };

          // Iterate through the keys of the sub-object
          for (const subKey of Object.keys(subObj)) {
            const subArray = subObj[subKey];
            const persistedSubArray = persistedSubObj[subKey] || [];

            // Merge the two arrays
            const mergedSubArray = [...subArray];
            for (const obj of persistedSubArray) {
              if (!mergedSubArray.some((o) => JSON.stringify(o) === JSON.stringify(obj))) {
                mergedSubArray.push(obj);
              }
            }

            mergedSubObj[subKey] = mergedSubArray;
          }

          mergedObj[key] = mergedSubObj;
        }
      }

      // Persist the merged object in the database
      await persistenceHelper.persist(mergedObj, databaseObjectsKey.key);
    }

    const permitFunctions = [
      ...txEvent.filterFunction(permitFunctionABI),
      ...txEvent.filterFunction(daiPermitFunctionABI),
      ...txEvent.filterFunction(uniswapPermitFunctionABI),
    ];

    // ERC20 and ERC721 approvals and transfers have the same signature
    // so we need to collect them seperately
    const approvalEvents = [
      ...txEvent.filterLog(approvalEventErc20ABI),
      ...txEvent.filterLog(approvalEventErc721ABI),
      ...txEvent.filterLog(approvalForAllEventABI),
    ];

    const transferEvents = [
      ...txEvent.filterLog(transferEventErc20ABI),
      ...txEvent.filterLog(transferEventErc721ABI),
      ...txEvent.filterLog(erc1155transferEventABI),
    ];

    await Promise.all([
      openseaHandleTransaction(txEvent, chainId, counters, findings, calculateAlertRate),
      sweepTokenHandleTransaction(txEvent, counters, chainId, findings, calculateAlertRate),
    ]);

    if (!approvalEvents.length && !permitFunctions.length && !transferEvents.length) {
      return findings;
    }

    await permitsHandleTransaction(
      txEvent,
      permitFunctions,
      counters,
      chainId,
      scamAddresses,
      cachedAddresses,
      provider,
      objects,
      scamSnifferDB,
      suspiciousContracts,
      findings,
      calculateAlertRate
    );
    await approvalsHandleTransaction(
      txEvent,
      chainId,
      approvalEvents,
      counters,
      objects,
      cachedERC1155Tokens,
      provider,
      scamAddresses,
      cachedAddresses,
      scamSnifferDB,
      isRelevantChain,
      suspiciousContracts,
      findings,
      calculateAlertRate
    );
    await transfersHandletransaction(
      txEvent,
      transferEvents,
      counters,
      chainId,
      objects,
      provider,
      isRelevantChain,
      persistenceHelper,
      databaseObjectsKey,
      scamAddresses,
      cachedAddresses,
      scamSnifferDB,
      suspiciousContracts,
      findings,
      calculateAlertRate
    );

    const et1 = new Date().getTime();
    if (et1 - st1 > 80) {
      console.log(`Time taken for transaction: ${et1 - st1} ms`, hash);
    }
    return findings;
  };

let lastTimestamp = 1678000000;
let init = false;
let suspiciousContracts = new Set();

const provideHandleBlock =
  (getSuspiciousContracts, persistenceHelper, databaseKeys, counters, objects) => async (blockEvent) => {
    const { timestamp, number } = blockEvent.block;

    if (!init) {
      suspiciousContracts = await getSuspiciousContracts(chainId, number, init);

      const scamSnifferResponse = await axios.get(
        "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json"
      );
      scamAddresses = scamSnifferResponse.data;
      // Convert to checksum addresses
      scamAddresses = scamAddresses.map((address) => ethers.utils.getAddress(address));

      init = true;
    } else if (number % 240 === 0) {
      let newSuspiciousContracts;
      try {
        newSuspiciousContracts = await getSuspiciousContracts(chainId, number, init);
      } catch {
        newSuspiciousContracts = new Set();
      }
      newSuspiciousContracts.forEach((contract) => suspiciousContracts.add(contract));
      const scamSnifferResponse = await axios.get(
        "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json"
      );
      scamAddresses = scamSnifferResponse.data;
      // Convert to checksum addresses
      scamAddresses = scamAddresses.map((address) => ethers.utils.getAddress(address));

      for (const key in counters) {
        await persistenceHelper.persist(counters[key], databaseKeys[key]);
      }
    }

    // Clean the data every timePeriodDays
    if (timestamp - lastTimestamp > TIME_PERIOD) {
      cleanData(objects, timestamp, TIME_PERIOD, cachedAddresses);
      lastTimestamp = timestamp;
    }
    return [];
  };

module.exports = {
  initialize: provideInitialize(
    getEthersProvider(),
    new PersistenceHelper(DATABASE_URL),
    DATABASE_KEYS,
    counters,
    DATABASE_OBJECT_KEY
  ),
  provideInitialize,
  provideHandleTransaction,
  handleTransaction: provideHandleTransaction(
    getEthersProvider(),
    counters,
    DATABASE_OBJECT_KEY,
    new PersistenceHelper(DATABASE_URL),
    objects,
    calculateAlertRate,
    lastBlock
  ),
  provideHandleBlock,
  handleBlock: provideHandleBlock(
    getSuspiciousContracts,
    new PersistenceHelper(DATABASE_URL),
    DATABASE_KEYS,
    counters,
    objects
  ),
  getCachedAddresses: () => cachedAddresses, // Exported for unit tests,
  getCachedERC1155Tokens: () => cachedERC1155Tokens, // Exported for unit tests,
  getSuspiciousContracts: () => suspiciousContracts, // Exported for unit tests
  counters,
  objects,
  resetLastTimestamp: () => {
    lastTimestamp = 0;
  },
  resetLastBlock: () => {
    lastBlock = 0;
  },
  resetInit: () => {
    init = false;
  },
  DATABASE_URL,
  DATABASE_KEYS,
  DATABASE_OBJECT_KEY,
};

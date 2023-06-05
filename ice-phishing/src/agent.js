const { ethers, getEthersProvider } = require("forta-agent");
const LRU = require("lru-cache");
const { default: axios } = require("axios");
const { default: calculateAlertRate } = require("bot-alert-rate");
const { ScanCountType } = require("bot-alert-rate");
const { ZETTABLOCK_API_KEY } = require("./keys");
const {
  createHighNumApprovalsAlertERC20,
  createHighNumApprovalsInfoAlertERC20,
  createHighNumApprovalsAlertERC721,
  createHighNumApprovalsInfoAlertERC721,
  createHighNumTransfersAlert,
  createHighNumTransfersLowSeverityAlert,
  createPermitTransferAlert,
  createPermitTransferMediumSeverityAlert,
  createApprovalForAllAlertERC721,
  createApprovalForAllInfoAlertERC721,
  createApprovalForAllAlertERC1155,
  createApprovalForAllInfoAlertERC1155,
  createPermitAlert,
  createPermitInfoAlert,
  createPermitScamAlert,
  createPermitScamCreatorAlert,
  // createPermitSuspiciousContractAlert,
  createApprovalScamAlert,
  createApprovalScamCreatorAlert,
  // createApprovalSuspiciousContractAlert,
  createTransferScamAlert,
  createSweepTokenAlert,
  createOpenseaAlert,
  getAddressType,
  getContractCreator,
  getBalance,
  getERC1155Balance,
  // getSuspiciousContracts,
  getTransactions,
  isOpenseaProxy,
  checkObjectSizeAndCleanup,
} = require("./helper");
const {
  approveCountThreshold,
  approveForAllCountThreshold,
  transferCountThreshold,
  maxAddressAlertsPerPeriod,
} = require("../bot-config.json");
const {
  TIME_PERIOD,
  ADDRESS_ZERO,
  IGNORED_ADDRESSES,
  safeBatchTransferFrom1155Sig,
  permitFunctionABI,
  daiPermitFunctionABI,
  uniswapPermitFunctionABI,
  pullFunctionABI,
  sweepTokenFunctionABI,
  approvalEventErc20ABI,
  approvalEventErc721ABI,
  approvalForAllEventABI,
  transferEventErc20ABI,
  transferEventErc721ABI,
  erc1155transferEventABI,
  upgradedEventABI,
  MAX_OBJECT_SIZE,
} = require("./utils");
const AddressType = require("./address-type");
const { PersistenceHelper } = require("./persistence.helper");

let scamAddresses = [];

// Every address is ~100B
// 100_000 addresses are 10MB
const cachedAddresses = new LRU({ max: 100_000 });

const cachedERC1155Tokens = new LRU({ max: 100_000 });

let chainId;
let isRelevantChain;
const BOT_ID = "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14";
let transactionsProcessed = 0;
let lastBlock = 0;
let scamSnifferDB = {
  data: {},
};

const DATABASE_URL = "https://research.forta.network/database/bot/";

const DATABASE_OBJECT_KEY = {
  key: "nm-icephishing-bot-objects-shard",
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
    const { hash, timestamp, blockNumber, from: f } = txEvent;

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

    const txFrom = ethers.utils.getAddress(f);

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

    if (Number(chainId) === 1) {
      const upgradedEvents = [...txEvent.filterLog(upgradedEventABI)];
      if (upgradedEvents.length) {
        counters.totalUpgrades += 1;
        // No other events will be emitted in the case of a malicious upgrade
        if (txEvent.logs.length === 1) {
          const {
            address,
            args: { implementation },
          } = upgradedEvents[0];
          const isOpensea = await isOpenseaProxy(address, blockNumber, chainId);
          if (isOpensea) {
            const attacker = await getContractCreator(implementation, chainId);
            const anomalyScore = await calculateAlertRate(
              chainId,
              BOT_ID,
              "ICE-PHISHING-OPENSEA-PROXY-UPGRADE",
              ScanCountType.CustomScanCount,
              counters.totalUpgrades
            );
            findings.push(createOpenseaAlert(txFrom, attacker, implementation, anomalyScore, hash));
          }
        }
      }
    }

    const pullFunctions = [...txEvent.filterFunction(pullFunctionABI)];
    const sweepTokenFunctions = [...txEvent.filterFunction(sweepTokenFunctionABI)];
    if (pullFunctions.length && sweepTokenFunctions.length) {
      counters.totalTransfers += 1;
      for (const [i, pullFunction] of pullFunctions.entries()) {
        const { token, value } = pullFunction.args;
        const { token: sweepToken, amountMinimum, recipient } = sweepTokenFunctions[i].args;
        if (token === sweepToken && value.toString() === amountMinimum.toString() && recipient !== txFrom) {
          const anomalyScore = await calculateAlertRate(
            chainId,
            BOT_ID,
            "ICE-PHISHING-PULL-SWEEPTOKEN",
            ScanCountType.CustomScanCount,
            counters.totalTransfers
          );
          findings.push(createSweepTokenAlert(txFrom, recipient, token, value, anomalyScore, hash));
          return findings;
        }
      }
    }

    if (!approvalEvents.length && !permitFunctions.length && !transferEvents.length) {
      return findings;
    }

    for (const func of permitFunctions) {
      counters.totalPermits += 1;

      let { address: asset } = func;
      let { owner, spender, deadline, value } = func.args;
      if (deadline) {
        deadline = Number(deadline.toString());
      }

      if (func.args.permitSingle) {
        spender = func.args.permitSingle.spender;
        deadline = Number(func.args.permitSingle.deadline.toString());
        value = func.args.permitSingle.details.value.toString();
        asset = func.args.permitSingle.details.token.toLowerCase();
      }

      if (txFrom === owner || IGNORED_ADDRESSES.includes(spender)) {
        continue;
      }

      const msgSenderType = await getAddressType(
        txFrom,
        scamAddresses,
        cachedAddresses,
        provider,
        blockNumber,
        chainId,
        false
      );

      const spenderType = await getAddressType(
        spender,
        scamAddresses,
        cachedAddresses,
        provider,
        blockNumber,
        chainId,
        false
      );

      if (
        (spenderType === AddressType.LowNumTxsUnverifiedContract ||
          spenderType === AddressType.EoaWithLowNonce ||
          spenderType === AddressType.ScamAddress) &&
        (msgSenderType === AddressType.LowNumTxsUnverifiedContract ||
          msgSenderType === AddressType.EoaWithLowNonce ||
          msgSenderType === AddressType.ScamAddress)
      ) {
        if (!objects.permissions[spender]) objects.permissions[spender] = [];
        objects.permissions[spender].push({
          asset,
          owner,
          hash,
          deadline,
          value: value ? value : 0,
        });
        if (spenderType !== AddressType.ScamAddress && msgSenderType !== AddressType.ScamAddress) {
          const anomalyScore = await calculateAlertRate(
            chainId,
            BOT_ID,
            "ICE-PHISHING-ERC20-PERMIT",
            ScanCountType.CustomScanCount,
            counters.totalPermits
          );
          findings.push(createPermitAlert(txFrom, spender, owner, asset, anomalyScore, hash));
        } else {
          const scamDomains = Object.keys(scamSnifferDB.data).filter(
            (key) =>
              scamSnifferDB.data[key].includes(txFrom.toLowerCase()) ||
              scamSnifferDB.data[key].includes(spender.toLowerCase())
          );
          let _scamAddresses = [];
          if (spenderType === AddressType.ScamAddress) {
            _scamAddresses.push(spender);
          }
          if (msgSenderType === AddressType.ScamAddress) {
            _scamAddresses.push(txFrom);
          }
          const anomalyScore = await calculateAlertRate(
            chainId,
            BOT_ID,
            "ICE-PHISHING-ERC20-SCAM-PERMIT",
            ScanCountType.CustomScanCount,
            counters.totalPermits
          );
          findings.push(
            createPermitScamAlert(txFrom, spender, owner, asset, _scamAddresses, scamDomains, anomalyScore, hash)
          );
        }
      } else if (
        spenderType === AddressType.LowNumTxsVerifiedContract ||
        spenderType === AddressType.EoaWithHighNonce
      ) {
        // const suspiciousContractFound = Array.from(suspiciousContracts).find(
        //   (contract) => contract.address === spender || contract.creator === spender
        // );

        // if (suspiciousContractFound) {
        //   const anomalyScore = await calculateAlertRate(
        //     chainId,
        //     BOT_ID,
        //     "ICE-PHISHING-ERC20-SUSPICIOUS-PERMIT",
        //     ScanCountType.CustomScanCount,
        //     counters.totalPermits
        //   );
        //   findings.push(
        //     createPermitSuspiciousContractAlert(
        //       txFrom,
        //       spender,
        //       owner,
        //       asset,
        //       suspiciousContractFound,
        //       anomalyScore,
        //       hash
        //     )
        //   );
        // }

        if (spenderType === AddressType.LowNumTxsVerifiedContract) {
          let spenderContractCreator, spenderContractCreatorType;

          spenderContractCreator = await getContractCreator(spender, chainId);
          if (spenderContractCreator) {
            spenderContractCreatorType = await getAddressType(
              spenderContractCreator,
              scamAddresses,
              cachedAddresses,
              provider,
              blockNumber,
              chainId,
              false
            );
          }

          if (spenderContractCreator && spenderContractCreatorType === AddressType.ScamAddress) {
            const scamDomains = Object.keys(scamSnifferDB.data).filter((key) =>
              scamSnifferDB.data[key].includes(spenderContractCreator.toLowerCase())
            );
            if (scamDomains.length > 0) {
              const anomalyScore = await calculateAlertRate(
                chainId,
                BOT_ID,
                "ICE-PHISHING-ERC20-SCAM-CREATOR-PERMIT",
                ScanCountType.CustomScanCount,
                counters.totalPermits
              );
              findings.push(
                createPermitScamCreatorAlert(
                  txFrom,
                  spender,
                  owner,
                  asset,
                  spenderContractCreator,
                  scamDomains,
                  anomalyScore,
                  hash
                )
              );
            }
          }
        }

        if (!objects.permissionsInfoSeverity[spender]) objects.permissionsInfoSeverity[spender] = [];
        objects.permissionsInfoSeverity[spender].push({
          asset,
          owner,
          hash,
          deadline,
          value: value ? value : 0,
        });
        const anomalyScore = await calculateAlertRate(
          chainId,
          BOT_ID,
          "ICE-PHISHING-ERC20-PERMIT-INFO",
          ScanCountType.CustomScanCount,
          counters.totalPermits
        );
        findings.push(createPermitInfoAlert(txFrom, spender, owner, asset, anomalyScore, hash));
      }
    }

    for (const event of approvalEvents) {
      counters.totalApprovals += 1;

      const { address: asset, name } = event;
      const { owner, spender, value, tokenId, approved } = event.args;

      const isApprovalForAll = name === "ApprovalForAll";

      // Filter out approval revokes
      if (isApprovalForAll && !approved) continue;
      if (value?.eq(0)) continue;
      if (spender === ADDRESS_ZERO) continue;
      if (IGNORED_ADDRESSES.includes(spender)) continue;

      // When transfering ERC20 tokens an Approval event is emitted with lower value
      // We should ignore these Approval events because they are duplicates
      const isAlreadyApproved = tokenId ? false : objects.approvals[spender]?.some((a) => a.owner === owner);

      if (isAlreadyApproved) continue;

      let isAssetERC1155 = false;

      if (!isApprovalForAll) {
        counters[`totalERC${tokenId ? "721" : "20"}Approvals`] += 1;
      } else {
        if (cachedERC1155Tokens.get(asset) === undefined) {
          let assetCode,
            tries = 0;
          while (tries < 3) {
            try {
              assetCode = await provider.getCode(asset);
              break;
            } catch (err) {
              tries++;
              if (tries === 3) throw err;
              console.log(`Attempt ${tries} to get the code failed, retrying...`);
              await new Promise((resolve) => setTimeout(resolve, 1000));
            }
          }
          cachedERC1155Tokens.set(asset, assetCode.includes(safeBatchTransferFrom1155Sig));
        }
        isAssetERC1155 = cachedERC1155Tokens.get(asset);
        counters[`totalERC${isAssetERC1155 ? "1155" : "721"}ApprovalsForAll`] += 1;
      }

      // Skip if the owner is not EOA
      const ownerType = await getAddressType(
        owner,
        scamAddresses,
        cachedAddresses,
        provider,
        blockNumber,
        chainId,
        true
      );

      if (
        ownerType === AddressType.LowNumTxsUnverifiedContract ||
        ownerType === AddressType.HighNumTxsUnverifiedContract ||
        ownerType === AddressType.LowNumTxsVerifiedContract ||
        ownerType === AddressType.HighNumTxsVerifiedContract
      ) {
        continue;
      }

      // Skip if the spender
      // is verified contract with high number of txs
      // is unverified contract with high number of txs
      // or is ignored address
      const spenderType = await getAddressType(
        spender,
        scamAddresses,
        cachedAddresses,
        provider,
        blockNumber,
        chainId,
        false
      );

      if (
        !spenderType ||
        spenderType === AddressType.HighNumTxsVerifiedContract ||
        spenderType === AddressType.HighNumTxsUnverifiedContract ||
        spenderType.startsWith("Ignored")
      ) {
        continue;
      }

      if (spenderType === AddressType.EoaWithHighNonce || spenderType === AddressType.LowNumTxsVerifiedContract) {
        // Initialize the approvals array for the spender if it doesn't exist
        if (!objects.approvalsInfoSeverity[spender]) objects.approvalsInfoSeverity[spender] = [];
      } else {
        if (!objects.approvals[spender]) objects.approvals[spender] = [];
      }

      const approval = { asset, owner, hash, timestamp };

      if (spenderType === AddressType.EoaWithHighNonce || spenderType === AddressType.LowNumTxsVerifiedContract) {
        if (isApprovalForAll) {
          if (isAssetERC1155) {
            if (!objects.approvalsForAll1155InfoSeverity[spender])
              objects.approvalsForAll1155InfoSeverity[spender] = [];
            objects.approvalsForAll1155InfoSeverity[spender].push(approval);
          } else {
            if (!objects.approvalsForAll721InfoSeverity[spender]) objects.approvalsForAll721InfoSeverity[spender] = [];
            objects.approvalsForAll721InfoSeverity[spender].push(approval);
          }
        } else if (tokenId) {
          if (!objects.approvalsERC721InfoSeverity[spender]) objects.approvalsERC721InfoSeverity[spender] = [];
          objects.approvalsERC721InfoSeverity[spender].push(approval);
        } else {
          if (!objects.approvalsERC20InfoSeverity[spender]) objects.approvalsERC20InfoSeverity[spender] = [];
          objects.approvalsERC20InfoSeverity[spender].push(approval);
        }
        // Update the approvals for the spender
        objects.approvalsInfoSeverity[spender].push({
          asset,
          owner,
          hash,
          timestamp,
          tokenId,
          isApprovalForAll,
        });
      } else {
        if (isApprovalForAll) {
          if (isAssetERC1155) {
            if (!objects.approvalsForAll1155[spender]) objects.approvalsForAll1155[spender] = [];
            objects.approvalsForAll1155[spender].push(approval);
          } else {
            if (!objects.approvalsForAll721[spender]) objects.approvalsForAll721[spender] = [];
            objects.approvalsForAll721[spender].push(approval);
          }
        } else if (tokenId) {
          if (!objects.approvalsERC721[spender]) objects.approvalsERC721[spender] = [];
          objects.approvalsERC721[spender].push(approval);
        } else {
          if (!objects.approvalsERC20[spender]) objects.approvalsERC20[spender] = [];
          objects.approvalsERC20[spender].push(approval);
        }
        // Update the approvals for the spender
        objects.approvals[spender].push({
          asset,
          owner,
          hash,
          timestamp,
          tokenId,
          isApprovalForAll,
        });
      }
      console.log("Detected possible malicious approval");
      console.log(`owner: ${owner}`);
      console.log(`spender: ${spender}`);
      console.log(`asset: ${asset}`);

      for (const _approvals of [
        objects.approvalsERC20,
        objects.approvalsERC721,
        objects.approvalsForAll721,
        objects.approvalsForAll1155,
        objects.approvals,
        objects.approvalsERC20InfoSeverity,
        objects.approvalsERC721InfoSeverity,
        objects.approvalsForAll721InfoSeverity,
        objects.approvalsForAll1155InfoSeverity,
        objects.approvalsInfoSeverity,
      ]) {
        if (!_approvals[spender]) continue;
        _approvals[spender].filter((a) => timestamp - a.timestamp < TIME_PERIOD);
      }

      if (
        spenderType === AddressType.ScamAddress ||
        spenderType === AddressType.LowNumTxsVerifiedContract ||
        spenderType === AddressType.LowNumTxsUnverifiedContract ||
        spenderType === AddressType.EoaWithLowNonce
      ) {
        if (spenderType === AddressType.ScamAddress) {
          const scamDomains = Object.keys(scamSnifferDB.data).filter((key) =>
            scamSnifferDB.data[key].includes(spender.toLowerCase())
          );
          const anomalyScore = await calculateAlertRate(
            chainId,
            BOT_ID,
            "ICE-PHISHING-SCAM-APPROVAL",
            isRelevantChain ? ScanCountType.CustomScanCount : ScanCountType.ErcApprovalCount,
            counters.totalApprovals
          );
          findings.push(createApprovalScamAlert(spender, owner, asset, scamDomains, anomalyScore, hash));
        } else {
          // const suspiciousContractFound = Array.from(suspiciousContracts).find(
          //   (contract) => contract.address === spender || contract.creator === spender
          // );
          // if (suspiciousContractFound) {
          //   const anomalyScore = await calculateAlertRate(
          //     chainId,
          //     BOT_ID,
          //     "ICE-PHISHING-SUSPICIOUS-APPROVAL",
          //     isRelevantChain ? ScanCountType.CustomScanCount : ScanCountType.ErcApprovalCount,
          //     counters.totalApprovals
          //   );
          //   findings.push(
          //     createApprovalSuspiciousContractAlert(
          //       spender,
          //       owner,
          //       asset,
          //       suspiciousContractFound.address,
          //       suspiciousContractFound.creator,
          //       anomalyScore,
          //       hash
          //     )
          //   );
          // }

          if (
            spenderType === AddressType.LowNumTxsVerifiedContract ||
            spenderType === AddressType.LowNumTxsUnverifiedContract
          ) {
            const spenderContractCreator = await getContractCreator(spender, chainId);
            if (spenderContractCreator && scamAddresses.includes(ethers.utils.getAddress(spenderContractCreator))) {
              const scamDomains = Object.keys(scamSnifferDB.data).filter((key) =>
                scamSnifferDB.data[key].includes(spenderContractCreator.toLowerCase())
              );
              const anomalyScore = await calculateAlertRate(
                chainId,
                BOT_ID,
                "ICE-PHISHING-SCAM-CREATOR-APPROVAL",
                isRelevantChain ? ScanCountType.CustomScanCount : ScanCountType.ErcApprovalCount,
                counters.totalApprovals
              );
              findings.push(
                createApprovalScamCreatorAlert(
                  spender,
                  spenderContractCreator,
                  owner,
                  asset,
                  scamDomains,
                  anomalyScore,
                  hash
                )
              );
            }
          }
        }
      }

      // Ignore the address until the end of the period if there are a lot of approvals
      if (objects.approvals[spender] && objects.approvals[spender].length > maxAddressAlertsPerPeriod) {
        const newType =
          spenderType === AddressType.EoaWithLowNonce ? AddressType.IgnoredEoa : AddressType.IgnoredContract;
        cachedAddresses.set(spender, newType);
      } else if (
        objects.approvalsInfoSeverity[spender] &&
        objects.approvalsInfoSeverity[spender].length > maxAddressAlertsPerPeriod
      ) {
        const newType =
          spenderType === AddressType.EoaWithHighNonce ? AddressType.IgnoredEoa : AddressType.IgnoredContract;
        cachedAddresses.set(spender, newType);
      }

      if (spenderType === AddressType.EoaWithHighNonce || spenderType === AddressType.LowNumTxsVerifiedContract) {
        if (
          objects.approvalsERC20InfoSeverity[spender] &&
          objects.approvalsERC20InfoSeverity[spender].length > approveCountThreshold
        ) {
          const anomalyScore = await calculateAlertRate(
            chainId,
            BOT_ID,
            "ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS-INFO",
            ScanCountType.CustomScanCount,
            counters.totalERC20Approvals
          );
          findings.push(
            createHighNumApprovalsInfoAlertERC20(spender, objects.approvalsInfoSeverity[spender], anomalyScore)
          );
        }

        if (
          objects.approvalsERC721InfoSeverity[spender] &&
          objects.approvalsERC721InfoSeverity[spender].length > approveCountThreshold
        ) {
          const anomalyScore = await calculateAlertRate(
            chainId,
            BOT_ID,
            "ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS-INFO",
            ScanCountType.CustomScanCount,
            counters.totalERC721Approvals
          );
          findings.push(
            createHighNumApprovalsInfoAlertERC721(spender, objects.approvalsInfoSeverity[spender], anomalyScore)
          );
        }

        if (isApprovalForAll) {
          if (
            objects.approvalsForAll721InfoSeverity[spender] &&
            objects.approvalsForAll721InfoSeverity[spender].length > approveForAllCountThreshold
          ) {
            const anomalyScore = await calculateAlertRate(
              chainId,
              BOT_ID,
              "ICE-PHISHING-ERC721-APPROVAL-FOR-ALL-INFO",
              ScanCountType.CustomScanCount,
              counters.totalERC721ApprovalsForAll
            );
            findings.push(createApprovalForAllInfoAlertERC721(spender, owner, asset, anomalyScore, hash));
          } else if (
            objects.approvalsForAll1155InfoSeverity[spender] &&
            objects.approvalsForAll1155InfoSeverity[spender].length > approveForAllCountThreshold
          ) {
            const anomalyScore = await calculateAlertRate(
              chainId,
              BOT_ID,
              "ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL-INFO",
              ScanCountType.CustomScanCount,
              counters.totalERC1155ApprovalsForAll
            );
            findings.push(createApprovalForAllInfoAlertERC1155(spender, owner, asset, anomalyScore, hash));
          }
        }
      } else {
        if (objects.approvalsERC20[spender] && objects.approvalsERC20[spender].length > approveCountThreshold) {
          const anomalyScore = await calculateAlertRate(
            chainId,
            BOT_ID,
            "ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS",
            ScanCountType.CustomScanCount,
            counters.totalERC20Approvals
          );
          findings.push(createHighNumApprovalsAlertERC20(spender, objects.approvals[spender], anomalyScore));
        }

        if (objects.approvalsERC721[spender] && objects.approvalsERC721[spender].length > approveCountThreshold) {
          const anomalyScore = await calculateAlertRate(
            chainId,
            BOT_ID,
            "ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS",
            ScanCountType.CustomScanCount,
            counters.totalERC721Approvals
          );
          findings.push(createHighNumApprovalsAlertERC721(spender, objects.approvals[spender], anomalyScore));
        }

        if (isApprovalForAll) {
          if (
            objects.approvalsForAll721[spender] &&
            objects.approvalsForAll721[spender].length > approveForAllCountThreshold
          ) {
            const anomalyScore = await calculateAlertRate(
              chainId,
              BOT_ID,
              "ICE-PHISHING-ERC721-APPROVAL-FOR-ALL",
              ScanCountType.CustomScanCount,
              counters.totalERC721ApprovalsForAll
            );
            findings.push(createApprovalForAllAlertERC721(spender, owner, asset, anomalyScore, hash));
          } else if (
            objects.approvalsForAll1155[spender] &&
            objects.approvalsForAll1155[spender].length > approveForAllCountThreshold
          ) {
            const anomalyScore = await calculateAlertRate(
              chainId,
              BOT_ID,
              "ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL",
              ScanCountType.CustomScanCount,
              counters.totalERC1155ApprovalsForAll
            );
            findings.push(createApprovalForAllAlertERC1155(spender, owner, asset, anomalyScore, hash));
          }
        }
      }
    }

    for (const event of transferEvents) {
      counters.totalTransfers += 1;
      const asset = event.address;
      const { from, to, value, values, tokenId, tokenIds } = event.args;

      // Filter out direct transfers, mints and burns
      if (from === txFrom || from === ADDRESS_ZERO || to === ADDRESS_ZERO) {
        continue;
      }

      let _scamAddresses = [];
      if (scamAddresses.includes(txFrom)) {
        if (!cachedAddresses.has(txFrom) || cachedAddresses.get(txFrom) !== AddressType.ScamAddress) {
          cachedAddresses.set(txFrom, AddressType.ScamAddress);
        }
        _scamAddresses.push(txFrom);
      }
      if (scamAddresses.includes(to)) {
        if (!cachedAddresses.has(to) || cachedAddresses.get(to) !== AddressType.ScamAddress) {
          cachedAddresses.set(to, AddressType.ScamAddress);
        }
        _scamAddresses.push(to);
      }

      if (_scamAddresses.length > 0) {
        const scamDomains = Object.keys(scamSnifferDB.data).filter(
          (key) =>
            scamSnifferDB.data[key].includes(txFrom.toLowerCase()) || scamSnifferDB.data[key].includes(to.toLowerCase())
        );
        const anomalyScore = await calculateAlertRate(
          chainId,
          BOT_ID,
          "ICE-PHISHING-SCAM-TRANSFER",
          isRelevantChain ? ScanCountType.CustomScanCount : ScanCountType.ErcTransferCount,
          counters.totalTransfers
        );
        findings.push(
          createTransferScamAlert(txFrom, from, to, asset, _scamAddresses, scamDomains, anomalyScore, hash)
        );
      }

      // Check if we monitor the spender
      const spenderApprovals = objects.approvals[txFrom];
      const spenderApprovalsInfoSeverity = objects.approvalsInfoSeverity[txFrom];
      const spenderPermissions = objects.permissions[txFrom];
      const spenderPermissionsInfoSeverity = objects.permissionsInfoSeverity[txFrom];
      if (!spenderApprovals && !spenderApprovalsInfoSeverity && !spenderPermissions && !spenderPermissionsInfoSeverity)
        continue;
      if (spenderPermissions) {
        await Promise.all(
          spenderPermissions.map(async (permission) => {
            if (permission.asset === asset && permission.owner === from && permission.deadline > timestamp) {
              if (!permission.value || ethers.BigNumber.from(permission.value).gte(ethers.BigNumber.from(value))) {
                const anomalyScore = await calculateAlertRate(
                  chainId,
                  BOT_ID,
                  "ICE-PHISHING-PERMITTED-ERC20-TRANSFER",
                  isRelevantChain ? ScanCountType.CustomScanCount : ScanCountType.ErcTransferCount,
                  counters.totalTransfers
                );
                findings.push(createPermitTransferAlert(txFrom, from, to, asset, value.toString(), anomalyScore, hash));
              }
            }
          })
        );
      }

      if (spenderPermissionsInfoSeverity) {
        await Promise.all(
          spenderPermissionsInfoSeverity.map(async (permission) => {
            if (permission.asset === asset && permission.owner === from && permission.deadline > timestamp) {
              if (!permission.value || ethers.BigNumber.from(permission.value).gte(ethers.BigNumber.from(value))) {
                const anomalyScore = await calculateAlertRate(
                  chainId,
                  BOT_ID,
                  "ICE-PHISHING-PERMITTED-ERC20-TRANSFER-MEDIUM",
                  isRelevantChain ? ScanCountType.CustomScanCount : ScanCountType.ErcTransferCount,
                  counters.totalTransfers
                );
                findings.push(
                  createPermitTransferMediumSeverityAlert(txFrom, from, to, asset, value, anomalyScore, hash)
                );
              }
            }
          })
        );
      }

      if (spenderApprovals) {
        // Check if we have caught the approval
        // For ERC20: Check if there is an approval from the owner that isn't from the current tx
        // For ERC721 & ERC1155: Check if the tokenId (or one of the tokenIds) is approved or if there is an ApprovalForAll
        const hasMonitoredApproval =
          tokenId || tokenIds
            ? spenderApprovals
                .filter((a) => a.owner === from)
                .some((a) => a.isApprovalForAll || a.tokenId.eq(tokenId) || tokenIds?.includes(a.tokenId))
            : spenderApprovals.find((a) => a.owner === from && a.asset === asset)?.timestamp < timestamp;
        if (!hasMonitoredApproval) continue;

        // Initialize the transfers array for the spender if it doesn't exist
        if (!objects.transfers[txFrom]) objects.transfers[txFrom] = [];

        console.log("Detected possible malicious transfer of approved assets");
        console.log(`owner: ${from}`);
        console.log(`spender: ${txFrom}`);
        console.log(`asset: ${asset}`);

        // Update the transfers for the spender
        objects.transfers[txFrom].push({
          asset,
          owner: from,
          hash,
          timestamp,
        });

        // Filter out old transfers
        objects.transfers[txFrom] = objects.transfers[txFrom].filter((a) => timestamp - a.timestamp < TIME_PERIOD);
        if (objects.transfers[txFrom].length > transferCountThreshold) {
          if (value || (values && values.length > 0)) {
            if (tokenIds) {
              tokenIds.forEach(async (tokenId) => {
                const balance = ethers.BigNumber.from(
                  await getERC1155Balance(asset, tokenId, from, provider, txEvent.blockNumber)
                );
                if (!balance.eq(0)) return;
              });
            } else if (tokenId) {
              const balance = ethers.BigNumber.from(
                await getERC1155Balance(asset, tokenId, from, provider, txEvent.blockNumber)
              );
              if (!balance.eq(0)) continue;
            } else {
              const balance = ethers.BigNumber.from(await getBalance(asset, from, provider, txEvent.blockNumber));
              if (!balance.eq(0)) continue;
            }
          }
          const anomalyScore = await calculateAlertRate(
            chainId,
            BOT_ID,
            "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS",
            isRelevantChain ? ScanCountType.CustomScanCount : ScanCountType.ErcTransferCount,
            counters.totalTransfers
          );
          findings.push(createHighNumTransfersAlert(txFrom, objects.transfers[txFrom], anomalyScore));
        }
      }

      if (spenderApprovalsInfoSeverity) {
        // Check if we have caught the approval
        // For ERC20: Check if there is an approval from the owner that isn't from the current tx
        // For ERC721: Check if the tokenId is approved or if there is an ApprovalForAll
        const hasMonitoredApproval =
          tokenId || tokenIds
            ? spenderApprovalsInfoSeverity
                .filter((a) => a.owner === from)
                .some((a) => a.isApprovalForAll || a.tokenId.eq(tokenId) || tokenIds?.includes(a.tokenId))
            : spenderApprovalsInfoSeverity.find((a) => a.owner === from && a.asset === asset)?.timestamp < timestamp;

        if (!hasMonitoredApproval) continue;

        // Initialize the transfers array for the spender if it doesn't exist
        if (!objects.transfersLowSeverity[txFrom]) objects.transfersLowSeverity[txFrom] = [];

        console.log("Detected possible malicious transfer of approved assets");
        console.log(`owner: ${from}`);
        console.log(`spender: ${txFrom}`);
        console.log(`asset: ${asset}`);

        // Update the transfers for the spender
        objects.transfersLowSeverity[txFrom].push({
          asset,
          owner: from,
          hash,
          timestamp,
        });

        // Filter out old transfers
        objects.transfersLowSeverity[txFrom] = objects.transfersLowSeverity[txFrom].filter(
          (a) => timestamp - a.timestamp < TIME_PERIOD
        );

        if (objects.transfersLowSeverity[txFrom].length > transferCountThreshold) {
          if (value || (values && values.length > 0)) {
            if (tokenIds) {
              tokenIds.forEach(async (tokenId) => {
                const balance = ethers.BigNumber.from(
                  await getERC1155Balance(asset, tokenId, from, provider, txEvent.blockNumber)
                );
                if (!balance.eq(0)) return;
              });
            } else if (tokenId) {
              const balance = ethers.BigNumber.from(
                await getERC1155Balance(asset, tokenId, from, provider, txEvent.blockNumber)
              );
              if (!balance.eq(0)) continue;
            } else {
              const balance = ethers.BigNumber.from(await getBalance(asset, from, provider, txEvent.blockNumber));
              if (!balance.eq(0)) continue;
            }
          }
          const anomalyScore = await calculateAlertRate(
            chainId,
            BOT_ID,
            "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS-LOW",
            isRelevantChain ? ScanCountType.CustomScanCount : ScanCountType.ErcTransferCount,
            counters.totalTransfers
          );
          findings.push(
            createHighNumTransfersLowSeverityAlert(txFrom, objects.transfersLowSeverity[txFrom], anomalyScore)
          );
        }
      }
    }

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

    const et1 = new Date().getTime();
    if (et1 - st1 > 80) {
      console.log(`Time taken for transaction: ${et1 - st1} ms`, hash);
    }
    return findings;
  };

let lastTimestamp = 1678000000;
let init = false;
// let suspiciousContracts = new Set();

const provideHandleBlock =
  (
    // getSuspiciousContracts,
    persistenceHelper,
    databaseKeys,
    counters,
    objects
  ) =>
  async (blockEvent) => {
    const { timestamp, number } = blockEvent.block;

    if (!init) {
      // suspiciousContracts = await getSuspiciousContracts(chainId, number, init);

      const scamSnifferResponse = await axios.get(
        "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json"
      );
      scamAddresses = scamSnifferResponse.data;
      // Convert to checksum addresses
      scamAddresses = scamAddresses.map((address) => ethers.utils.getAddress(address));

      init = true;
    } else if (number % 240 === 0) {
      // let newSuspiciousContracts;
      // try {
      //   newSuspiciousContracts = await getSuspiciousContracts(chainId, number, init);
      // } catch {
      //   newSuspiciousContracts = new Set();
      // }
      // newSuspiciousContracts.forEach((contract) => suspiciousContracts.add(contract));
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
      console.log("Cleaning");
      console.log(`Approvals before: ${Object.keys(objects.approvals).length}`);
      console.log(`Approvals ERC20 before: ${Object.keys(objects.approvalsERC20).length}`);
      console.log(`Approvals ERC721 before: ${Object.keys(objects.approvalsERC721).length}`);
      console.log(`ApprovalsForAll ERC721 before: ${Object.keys(objects.approvalsForAll721).length}`);
      console.log(`ApprovalsForAll ERC1155 before: ${Object.keys(objects.approvalsForAll1155).length}`);
      console.log(`Permissions before: ${Object.keys(objects.permissions).length}`);
      console.log(`Transfers before: ${Object.keys(objects.transfers).length}`);
      console.log(`Approvals Info Severity before: ${Object.keys(objects.approvalsInfoSeverity).length}`);
      console.log(`Approvals ERC20 Info Severity before: ${Object.keys(objects.approvalsERC20InfoSeverity).length}`);
      console.log(`Approvals ERC721 Info Severity before: ${Object.keys(objects.approvalsERC721InfoSeverity).length}`);
      console.log(
        `ApprovalsForAll ERC721 Info Severity before: ${Object.keys(objects.approvalsForAll721InfoSeverity).length}`
      );
      console.log(
        `ApprovalsForAll ERC1155 Info Severity before: ${Object.keys(objects.approvalsForAll1155InfoSeverity).length}`
      );
      console.log(`Permissions Info Severity before: ${Object.keys(objects.permissionsInfoSeverity).length}`);
      console.log(`Transfers Low Severity before: ${Object.keys(objects.transfersLowSeverity).length}`);

      Object.entries(objects.approvals).forEach(([spender, data]) => {
        const { length } = data;
        // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
        if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
          delete objects.approvals[spender];
        }
      });

      Object.entries(objects.approvalsERC20).forEach(([spender, data]) => {
        const { length } = data;
        // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
        if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
          delete objects.approvalsERC20[spender];
        }
      });

      Object.entries(objects.approvalsERC721).forEach(([spender, data]) => {
        const { length } = data;
        // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
        if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
          delete objects.approvalsERC721[spender];
        }
      });

      Object.entries(objects.approvalsForAll721).forEach(([spender, data]) => {
        const { length } = data;
        // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
        if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
          delete objects.approvalsForAll721[spender];
        }
      });

      Object.entries(objects.approvalsForAll1155).forEach(([spender, data]) => {
        const { length } = data;
        // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
        if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
          delete objects.approvalsForAll1155[spender];
        }
      });

      Object.keys(objects.permissions).forEach((spender) => {
        objects.permissions[spender] = objects.permissions[spender].filter((entry) => entry.deadline > timestamp);
        if (!(objects.permissions[spender].length > 0)) {
          delete objects.permissions[spender];
        }
      });

      Object.entries(objects.transfers).forEach(([spender, data]) => {
        const { length } = data;
        // Clear the transfers if the last transfer from a spender is more than timePeriodDays ago
        if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
          delete objects.transfers[spender];
        }
      });

      Object.entries(objects.approvalsInfoSeverity).forEach(([spender, data]) => {
        const { length } = data;
        // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
        if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
          delete objects.approvalsInfoSeverity[spender];
        }
      });

      Object.entries(objects.approvalsERC20InfoSeverity).forEach(([spender, data]) => {
        const { length } = data;
        // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
        if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
          delete objects.approvalsERC20InfoSeverity[spender];
        }
      });

      Object.entries(objects.approvalsERC721InfoSeverity).forEach(([spender, data]) => {
        const { length } = data;
        // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
        if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
          delete objects.approvalsERC721InfoSeverity[spender];
        }
      });

      Object.entries(objects.approvalsForAll721InfoSeverity).forEach(([spender, data]) => {
        const { length } = data;
        // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
        if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
          delete objects.approvalsForAll721InfoSeverity[spender];
        }
      });

      Object.entries(objects.approvalsForAll1155InfoSeverity).forEach(([spender, data]) => {
        const { length } = data;
        // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
        if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
          delete objects.approvalsForAll1155InfoSeverity[spender];
        }
      });

      Object.keys(objects.permissionsInfoSeverity).forEach((spender) => {
        objects.permissionsInfoSeverity[spender] = objects.permissionsInfoSeverity[spender].filter(
          (entry) => entry.deadline > timestamp
        );
        if (!(objects.permissionsInfoSeverity[spender].length > 0)) {
          delete objects.permissionsInfoSeverity[spender];
        }
      });

      Object.entries(objects.transfersLowSeverity).forEach(([spender, data]) => {
        const { length } = data;
        // Clear the transfers if the last transfer from a spender is more than timePeriodDays ago
        if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
          delete objects.transfersLowSeverity[spender];
        }
      });

      console.log(`Approvals after: ${Object.keys(objects.approvals).length}`);
      console.log(`Approvals ERC20 after: ${Object.keys(objects.approvalsERC20).length}`);
      console.log(`Approvals ERC721 after: ${Object.keys(objects.approvalsERC721).length}`);
      console.log(`ApprovalsForAll ERC721 after: ${Object.keys(objects.approvalsForAll721).length}`);
      console.log(`ApprovalsForAll ERC1155 after: ${Object.keys(objects.approvalsForAll1155).length}`);
      console.log(`Permissions after: ${Object.keys(objects.permissions).length}`);
      console.log(`Transfers after: ${Object.keys(objects.transfers).length}`);
      console.log(`Approvals Info Severity after: ${Object.keys(objects.approvalsInfoSeverity).length}`);
      console.log(`Approvals ERC20 Info Severity after: ${Object.keys(objects.approvalsERC20InfoSeverity).length}`);
      console.log(`Approvals ERC721 Info Severity after: ${Object.keys(objects.approvalsERC721InfoSeverity).length}`);
      console.log(
        `ApprovalsForAll ERC721 Info Severity after: ${Object.keys(objects.approvalsForAll721InfoSeverity).length}`
      );
      console.log(
        `ApprovalsForAll ERC1155 Info Severity after: ${Object.keys(objects.approvalsForAll1155InfoSeverity).length}`
      );
      console.log(`Permissions Info Severity after: ${Object.keys(objects.permissionsInfoSeverity).length}`);
      console.log(`Transfers Low Severity after: ${Object.keys(objects.transfersLowSeverity).length}`);

      // Reset ignored addresses
      cachedAddresses.entries(([address, type]) => {
        if (type === AddressType.IgnoredEoa) {
          cachedAddresses.set(address, AddressType.EoaWithLowNonce);
        }

        if (type === AddressType.IgnoredContract) {
          cachedAddresses.set(address, AddressType.LowNumTxsUnverifiedContract);
        }
      });

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
    // getSuspiciousContracts,
    new PersistenceHelper(DATABASE_URL),
    DATABASE_KEYS,
    counters,
    objects
  ),
  getCachedAddresses: () => cachedAddresses, // Exported for unit tests,
  getCachedERC1155Tokens: () => cachedERC1155Tokens, // Exported for unit tests,
  // getSuspiciousContracts: () => suspiciousContracts, // Exported for unit tests
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

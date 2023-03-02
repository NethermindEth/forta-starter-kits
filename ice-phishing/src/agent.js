const { ethers, getEthersProvider } = require("forta-agent");
const LRU = require("lru-cache");
const { default: axios } = require("axios");
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
  createPermitSuspiciousContractAlert,
  createApprovalScamAlert,
  createApprovalScamCreatorAlert,
  createApprovalSuspiciousContractAlert,
  createTransferScamAlert,
  createTransferScamCreatorAlert,
  createTransferSuspiciousContractAlert,
  getAddressType,
  getContractCreator,
  getBalance,
  getERC1155Balance,
  getSuspiciousContracts,
  getTransactions,
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
  MAX_OBJECT_SIZE,
  safeBatchTransferFrom1155Sig,
  permitFunctionABI,
  daiPermitFunctionABI,
  approvalEventErc20ABI,
  approvalEventErc721ABI,
  approvalForAllEventABI,
  transferEventErc20ABI,
  transferEventErc721ABI,
  erc1155transferEventABI,
} = require("./utils");
const AddressType = require("./address-type");
const { PersistenceHelper } = require("./persistence.helper");

let approvals = {};
const approvalsERC20 = {};
const approvalsERC721 = {};
const approvalsForAll721 = {};
const approvalsForAll1155 = {};
const approvalsInfoSeverity = {};
const approvalsERC20InfoSeverity = {};
const approvalsERC721InfoSeverity = {};
const approvalsForAll721InfoSeverity = {};
const approvalsForAll1155InfoSeverity = {};
const permissions = {};
const permissionsInfoSeverity = {};
const transfers = {};
const transfersLowSeverity = {};

let scamAddresses = [];

// Every address is ~100B
// 100_000 addresses are 10MB
const cachedAddresses = new LRU({ max: 100_000 });

const cachedERC1155Tokens = new LRU({ max: 100_000 });

let chainId;

let transactionsProcessed = 0;
let lastBlock = 0;
let scamSnifferDB = {
  data: {},
};

const DATABASE_URL = "https://research.forta.network/database/bot/";

const DATABASE_OBJECTS_KEYS = {
  approvals: "nm-icephishing-bot-approvals-key",
  approvalsERC20: "nm-icephishing-bot-approvals-erc20-key",
  approvalsERC721: "nm-icephishing-bot-approvals-erc721-key",
  approvalsForAll721: "nm-icephishing-bot-approvals-for-all-721-key",
  approvalsForAll1155: "nm-icephishing-bot-approvals-for-all-1155-key",
  approvalsInfoSeverity: "nm-icephishing-bot-approvals-info-severity-key",
  approvalsERC20InfoSeverity: "nm-icephishing-bot-approvals-erc20-info-severity-key",
  approvalsERC721InfoSeverity: "nm-icephishing-bot-approvals-erc721-info-severity-key",
  approvalsForAll721InfoSeverity: "nm-icephishing-bot-approvals-for-all-721-info-severity-key",
  approvalsForAll1155InfoSeverity: "nm-icephishing-bot-approvals-for-all-1155-info-severity-key",
  permissions: "nm-icephishing-bot-permissions-key",
  permissionsInfoSeverity: "nm-icephishing-bot-permissions-info-severity-key",
  transfers: "nm-icephishing-bot-transfers-key",
  transfersLowSeverity: "nm-icephishing-bot-transfers-low-severity-key",
};

const objectsArray = [
  approvals,
  approvalsERC20,
  approvalsERC721,
  approvalsForAll721,
  approvalsForAll1155,
  approvalsInfoSeverity,
  approvalsERC20InfoSeverity,
  approvalsERC721InfoSeverity,
  approvalsForAll721InfoSeverity,
  approvalsForAll1155InfoSeverity,
  permissions,
  permissionsInfoSeverity,
  transfers,
  transfersLowSeverity,
];

const DATABASE_KEYS = {
  totalPermits: "nm-icephishing-bot-total-permits-key",
  totalApprovals: "nm-icephishing-bot-total-approvals-key",
  totalTransfers: "nm-icephishing-bot-total-transfers-key",
  totalERC20Approvals: "nm-icephishing-bot-total-erc20-approvals-key",
  totalERC721Approvals: "nm-icephishing-bot-total-erc721-approvals-key",
  totalERC721ApprovalsForAll: "nm-icephishing-bot-total-erc721-approvalsforall-key",
  totalERC1155ApprovalsForAll: "nm-icephishing-bot-total-erc1155-approvalsforall-key",
  detectedPermits: "nm-icephishing-bot-detect-permits-key",
  detectedPermitsInfo: "nm-icephishing-bot-detect-permits-info-key",
  detectedScamPermits: "nm-icephishing-bot-detect-scam-permits-key",
  detectedScamCreatorPermits: "nm-icephishing-bot-detect-scam-creator-permits-key",
  detectedSuspiciousPermits: "nm-icephishing-bot-detect-suspicious-permits-key",
  detectedERC20Approvals: "nm-icephishing-bot-detect-erc20-approvals-key",
  detectedERC20ApprovalsInfo: "nm-icephishing-bot-detect-erc20-approvals-info-key",
  detectedERC721Approvals: "nm-icephishing-bot-detect-erc721-approvals-key",
  detectedERC721ApprovalsInfo: "nm-icephishing-bot-detect-erc721-approvals-info-key",
  detectedERC721ApprovalsForAll: "nm-icephishing-bot-detect-erc721-approvalsforall-key",
  detectedERC721ApprovalsForAllInfo: "nm-icephishing-bot-detect-erc721-approvalsforall-info-key",
  detectedERC1155ApprovalsForAll: "nm-icephishing-bot-detect-erc1155-approvalsforall-key",
  detectedERC1155ApprovalsForAllInfo: "nm-icephishing-bot-detect-erc1155-approvalsforall-info-key",
  detectedScamApprovals: "nm-icephishing-bot-detect-scam-approvals-key",
  detectedScamCreatorApprovals: "nm-icephishing-bot-detect-scam-creator-approvals-key",
  detectedSuspiciousApprovals: "nm-icephishing-bot-detect-suspicious-approvals-key",
  detectedTransfers: "nm-icephishing-bot-detect-transfers-key",
  detectedTransfersLow: "nm-icephishing-bot-detect-transfers-low-key",
  detectedPermittedTransfers: "nm-icephishing-bot-detect-permitted-transfers-key",
  detectedPermittedTransfersMedium: "nm-icephishing-bot-detect-permitted-transfers-medium-key",
  detectedScamTransfers: "nm-icephishing-bot-detect-scam-transfers-key",
  detectedScamCreatorTransfers: "nm-icephishing-bot-detect-scam-creator-transfers-key",
  detectedSuspiciousTransfers: "nm-icephishing-bot-detect-suspicious-transfers-key",
};

const counters = {
  totalPermits: 0,
  totalApprovals: 0,
  totalTransfers: 0,
  totalERC20Approvals: 0,
  totalERC721Approvals: 0,
  totalERC721ApprovalsForAll: 0,
  totalERC1155ApprovalsForAll: 0,
  detectedPermits: 0,
  detectedPermitsInfo: 0,
  detectedScamPermits: 0,
  detectedScamCreatorPermits: 0,
  detectedSuspiciousPermits: 0,
  detectedERC20Approvals: 0,
  detectedERC20ApprovalsInfo: 0,
  detectedERC721Approvals: 0,
  detectedERC721ApprovalsInfo: 0,
  detectedERC721ApprovalsForAll: 0,
  detectedERC721ApprovalsForAllInfo: 0,
  detectedERC1155ApprovalsForAll: 0,
  detectedERC1155ApprovalsForAllInfo: 0,
  detectedScamApprovals: 0,
  detectedScamCreatorApprovals: 0,
  detectedSuspiciousApprovals: 0,
  detectedTransfers: 0,
  detectedTransfersLow: 0,
  detectedPermittedTransfers: 0,
  detectedPermittedTransfersMedium: 0,
  detectedScamTransfers: 0,
  detectedScamCreatorTransfers: 0,
  detectedSuspiciousTransfers: 0,
};

const provideInitialize = (provider, persistenceHelper, databaseKeys, counters) => {
  return async () => {
    ({ chainId } = await provider.getNetwork());

    Object.keys(databaseKeys).forEach((key) => {
      databaseKeys[key] = `${databaseKeys[key]}-${chainId}`;
    });

    for (const key in counters) {
      counters[key] = await persistenceHelper.load(databaseKeys[key]);
    }
  };
};
let currentTx = 0;
let transactions = [];

const provideHandleTransaction = (provider, counters, persistenceHelper) => async (txEvent) => {
  const findings = [];

  const { hash, timestamp, blockNumber, from: f } = txEvent;

  // console.log(transactions.length, transactions);

  // console.log(transactions[currentTx].hash === hash);
  // if (currentTx === transactions.length - 1) {
  //   currentTx = 0;
  // } else {
  //   currentTx++;
  // }

  if (blockNumber != lastBlock) {
    objectsArray.forEach((obj) => {
      // Load objects
    });

    if (blockNumber % 100 == 0 || lastBlock === 0) {
      scamSnifferDB = await axios.get(
        "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/combined.json"
      );
    }

    transactions = await getTransactions(provider, blockNumber);

    // objectsArray.forEach((obj) => checkObjectSizeAndCleanup(obj));

    lastBlock = blockNumber;
    console.log(`-----Transactions processed in block ${blockNumber - 1}: ${transactionsProcessed}-----`);
    transactionsProcessed = 0;
  }
  transactionsProcessed += 1;

  const txFrom = ethers.utils.getAddress(f);

  const permitFunctions = [
    ...txEvent.filterFunction(permitFunctionABI),
    ...txEvent.filterFunction(daiPermitFunctionABI),
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

  if (approvalEvents.length === 0 && permitFunctions.length === 0 && transferEvents.length === 0) {
    return findings;
  }

  if (!chainId) {
    ({ chainId } = await provider.getNetwork());
  }

  await Promise.all(
    permitFunctions.map(async (func) => {
      counters.totalPermits += 1;

      const { address: asset } = func;
      const { owner, spender, deadline, expiry, value } = func.args;

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

      if (txFrom !== owner) {
        if (
          (spenderType === AddressType.LowNumTxsUnverifiedContract ||
            spenderType === AddressType.EoaWithLowNonce ||
            spenderType === AddressType.ScamAddress) &&
          (msgSenderType === AddressType.LowNumTxsUnverifiedContract ||
            msgSenderType === AddressType.EoaWithLowNonce ||
            msgSenderType === AddressType.ScamAddress)
        ) {
          if (!permissions[spender]) permissions[spender] = [];
          permissions[spender].push({
            asset,
            owner,
            hash,
            deadline: deadline ? deadline : expiry,
            value: value ? value : 0,
          });
          if (spenderType !== AddressType.ScamAddress && msgSenderType !== AddressType.ScamAddress) {
            counters.detectedPermits += 1;
            const anomalyScore = counters.detectedPermits / counters.totalPermits;
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
            counters.detectedScamPermits += 1;
            const anomalyScore = counters.detectedScamPermits / counters.totalPermits;
            findings.push(
              createPermitScamAlert(txFrom, spender, owner, asset, _scamAddresses, scamDomains, anomalyScore, hash)
            );
          }
        } else if (
          spenderType === AddressType.LowNumTxsVerifiedContract ||
          spenderType === AddressType.EoaWithHighNonce
        ) {
          const suspiciousContractFound = Array.from(suspiciousContracts).find(
            (contract) => contract.address === spender || contract.creator === spender
          );
          if (suspiciousContractFound) {
            counters.detectedSuspiciousPermits += 1;
            const anomalyScore = counters.detectedSuspiciousPermits / counters.totalPermits;
            findings.push(
              createPermitSuspiciousContractAlert(
                txFrom,
                spender,
                owner,
                asset,
                suspiciousContractFound,
                anomalyScore,
                hash
              )
            );
          }

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
                counters.detectedScamCreatorPermits += 1;
                const anomalyScore = counters.detectedScamCreatorPermits / counters.totalPermits;
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

          if (!permissionsInfoSeverity[spender]) permissionsInfoSeverity[spender] = [];
          permissionsInfoSeverity[spender].push({
            asset,
            owner,
            hash,
            deadline: deadline ? deadline : expiry,
            value: value ? value : 0,
          });
          counters.detectedPermitsInfo += 1;
          const anomalyScore = counters.detectedPermitsInfo / counters.totalPermits;
          findings.push(createPermitInfoAlert(txFrom, spender, owner, asset, anomalyScore, hash));
        }
      }
    })
  );

  await Promise.all(
    approvalEvents.map(async (event) => {
      counters.totalApprovals += 1;

      const { address: asset, name } = event;
      const { owner, spender, value, tokenId, approved } = event.args;

      const isApprovalForAll = name === "ApprovalForAll";

      // Filter out approval revokes
      if (isApprovalForAll && !approved) return;
      if (value?.eq(0)) return;
      if (spender === ADDRESS_ZERO) return;

      // When transfering ERC20 tokens an Approval event is emitted with lower value
      // We should ignore these Approval events because they are duplicates
      const isAlreadyApproved = tokenId ? false : approvals[spender]?.some((a) => a.owner === owner);

      if (isAlreadyApproved) return;

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
      )
        return;

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
        return;
      }

      if (spenderType === AddressType.EoaWithHighNonce || spenderType === AddressType.LowNumTxsVerifiedContract) {
        // Initialize the approvals array for the spender if it doesn't exist
        if (!approvalsInfoSeverity[spender]) approvalsInfoSeverity[spender] = [];
      } else {
        if (!approvals[spender]) approvals[spender] = [];
      }

      const approval = { asset, owner, hash, timestamp };

      if (spenderType === AddressType.EoaWithHighNonce || spenderType === AddressType.LowNumTxsVerifiedContract) {
        if (isApprovalForAll) {
          if (isAssetERC1155) {
            if (!approvalsForAll1155InfoSeverity[spender]) approvalsForAll1155InfoSeverity[spender] = [];
            approvalsForAll1155InfoSeverity[spender].push(approval);
          } else {
            if (!approvalsForAll721InfoSeverity[spender]) approvalsForAll721InfoSeverity[spender] = [];
            approvalsForAll721InfoSeverity[spender].push(approval);
          }
        } else if (tokenId) {
          if (!approvalsERC721InfoSeverity[spender]) approvalsERC721InfoSeverity[spender] = [];
          approvalsERC721InfoSeverity[spender].push(approval);
        } else {
          if (!approvalsERC20InfoSeverity[spender]) approvalsERC20InfoSeverity[spender] = [];
          approvalsERC20InfoSeverity[spender].push(approval);
        }

        // Update the approvals for the spender
        approvalsInfoSeverity[spender].push({
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
            if (!approvalsForAll1155[spender]) approvalsForAll1155[spender] = [];
            approvalsForAll1155[spender].push(approval);
          } else {
            if (!approvalsForAll721[spender]) approvalsForAll721[spender] = [];
            approvalsForAll721[spender].push(approval);
          }
        } else if (tokenId) {
          if (!approvalsERC721[spender]) approvalsERC721[spender] = [];
          approvalsERC721[spender].push(approval);
        } else {
          if (!approvalsERC20[spender]) approvalsERC20[spender] = [];
          approvalsERC20[spender].push(approval);
        }

        // Update the approvals for the spender
        approvals[spender].push({
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
        approvalsERC20,
        approvalsERC721,
        approvalsForAll721,
        approvalsForAll1155,
        approvals,
        approvalsERC20InfoSeverity,
        approvalsERC721InfoSeverity,
        approvalsForAll721InfoSeverity,
        approvalsForAll1155InfoSeverity,
        approvalsInfoSeverity,
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
          counters.detectedScamApprovals += 1;
          const anomalyScore = counters.detectedScamApprovals / counters.totalApprovals;
          findings.push(createApprovalScamAlert(spender, owner, asset, scamDomains, anomalyScore, hash));
        } else {
          const suspiciousContractFound = Array.from(suspiciousContracts).find(
            (contract) => contract.address === spender || contract.creator === spender
          );
          if (suspiciousContractFound) {
            counters.detectedSuspiciousApprovals += 1;
            const anomalyScore = counters.detectedSuspiciousApprovals / counters.totalApprovals;
            findings.push(
              createApprovalSuspiciousContractAlert(
                spender,
                owner,
                asset,
                suspiciousContractFound.address,
                suspiciousContractFound.creator,
                anomalyScore,
                hash
              )
            );
          }

          if (
            spenderType === AddressType.LowNumTxsVerifiedContract ||
            spenderType === AddressType.LowNumTxsUnverifiedContract
          ) {
            const spenderContractCreator = await getContractCreator(spender, chainId);
            if (spenderContractCreator) {
              const scamDomains = Object.keys(scamSnifferDB.data).filter((key) =>
                scamSnifferDB.data[key].includes(spenderContractCreator.toLowerCase())
              );
              if (scamDomains.length > 0) {
                counters.detectedScamCreatorApprovals += 1;
                const anomalyScore = counters.detectedScamCreatorApprovals / counters.totalApprovals;
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
      }

      // Ignore the address until the end of the period if there are a lot of approvals
      if (approvals[spender] && approvals[spender].length > maxAddressAlertsPerPeriod) {
        const newType =
          spenderType === AddressType.EoaWithLowNonce ? AddressType.IgnoredEoa : AddressType.IgnoredContract;
        cachedAddresses.set(spender, newType);
      } else if (approvalsInfoSeverity[spender] && approvalsInfoSeverity[spender].length > maxAddressAlertsPerPeriod) {
        const newType =
          spenderType === AddressType.EoaWithHighNonce ? AddressType.IgnoredEoa : AddressType.IgnoredContract;
        cachedAddresses.set(spender, newType);
      }

      if (spenderType === AddressType.EoaWithHighNonce || spenderType === AddressType.LowNumTxsVerifiedContract) {
        if (approvalsERC20InfoSeverity[spender] && approvalsERC20InfoSeverity[spender].length > approveCountThreshold) {
          counters.detectedERC20ApprovalsInfo += approvalsERC20InfoSeverity[spender].length;
          let anomalyScore = counters.detectedERC20ApprovalsInfo / counters.totalERC20Approvals;
          anomalyScore = Math.min(anomalyScore, 1);
          findings.push(createHighNumApprovalsInfoAlertERC20(spender, approvalsInfoSeverity[spender], anomalyScore));
        }

        if (
          approvalsERC721InfoSeverity[spender] &&
          approvalsERC721InfoSeverity[spender].length > approveCountThreshold
        ) {
          counters.detectedERC721ApprovalsInfo += approvalsERC721InfoSeverity[spender].length;
          let anomalyScore = counters.detectedERC721ApprovalsInfo / counters.totalERC721Approvals;
          anomalyScore = Math.min(anomalyScore, 1);
          findings.push(createHighNumApprovalsInfoAlertERC721(spender, approvalsInfoSeverity[spender], anomalyScore));
        }

        if (isApprovalForAll) {
          if (
            approvalsForAll721InfoSeverity[spender] &&
            approvalsForAll721InfoSeverity[spender].length > approveForAllCountThreshold
          ) {
            counters.detectedERC721ApprovalsForAllInfo += approvalsForAll721InfoSeverity[spender].length;
            let anomalyScore = counters.detectedERC721ApprovalsForAllInfo / counters.totalERC721ApprovalsForAll;
            anomalyScore = Math.min(anomalyScore, 1);
            findings.push(createApprovalForAllInfoAlertERC721(spender, owner, asset, anomalyScore, hash));
          } else if (
            approvalsForAll1155InfoSeverity[spender] &&
            approvalsForAll1155InfoSeverity[spender].length > approveForAllCountThreshold
          ) {
            counters.detectedERC1155ApprovalsForAllInfo += approvalsForAll1155InfoSeverity[spender].length;
            let anomalyScore = counters.detectedERC1155ApprovalsForAllInfo / counters.totalERC1155ApprovalsForAll;
            anomalyScore = Math.min(anomalyScore, 1);
            findings.push(createApprovalForAllInfoAlertERC1155(spender, owner, asset, anomalyScore, hash));
          }
        }
      } else {
        if (approvalsERC20[spender] && approvalsERC20[spender].length > approveCountThreshold) {
          counters.detectedERC20Approvals += approvalsERC20[spender].length;
          let anomalyScore = counters.detectedERC20Approvals / counters.totalERC20Approvals;
          anomalyScore = Math.min(anomalyScore, 1);
          findings.push(createHighNumApprovalsAlertERC20(spender, approvals[spender], anomalyScore));
        }

        if (approvalsERC721[spender] && approvalsERC721[spender].length > approveCountThreshold) {
          counters.detectedERC721Approvals += approvalsERC721[spender].length;
          let anomalyScore = counters.detectedERC721Approvals / counters.totalERC721Approvals;
          anomalyScore = Math.min(anomalyScore, 1);
          findings.push(createHighNumApprovalsAlertERC721(spender, approvals[spender], anomalyScore));
        }

        if (isApprovalForAll) {
          if (approvalsForAll721[spender] && approvalsForAll721[spender].length > approveForAllCountThreshold) {
            counters.detectedERC721ApprovalsForAll += approvalsForAll721[spender].length;
            let anomalyScore = counters.detectedERC721ApprovalsForAll / counters.totalERC721ApprovalsForAll;
            anomalyScore = Math.min(anomalyScore, 1);
            findings.push(createApprovalForAllAlertERC721(spender, owner, asset, anomalyScore, hash));
          } else if (
            approvalsForAll1155[spender] &&
            approvalsForAll1155[spender].length > approveForAllCountThreshold
          ) {
            counters.detectedERC1155ApprovalsForAll += approvalsForAll1155[spender].length;
            let anomalyScore = counters.detectedERC1155ApprovalsForAll / counters.totalERC1155ApprovalsForAll;
            anomalyScore = Math.min(anomalyScore, 1);
            findings.push(createApprovalForAllAlertERC1155(spender, owner, asset, anomalyScore, hash));
          }
        }
      }
    })
  );

  await Promise.all(
    transferEvents.map(async (event) => {
      counters.totalTransfers += 1;
      const asset = event.address;
      const { from, to, value, values, tokenId, tokenIds } = event.args;

      // Filter out direct transfers and mints
      if (from === txFrom || from === ADDRESS_ZERO) return;

      const [txFromType, toType] = await Promise.all([
        getAddressType(txFrom, scamAddresses, cachedAddresses, provider, blockNumber, chainId, false),
        getAddressType(to, scamAddresses, cachedAddresses, provider, blockNumber, chainId, false),
      ]);

      if (txFromType === AddressType.ScamAddress || toType === AddressType.ScamAddress) {
        const scamDomains = Object.keys(scamSnifferDB.data).filter(
          (key) =>
            scamSnifferDB.data[key].includes(txFrom.toLowerCase()) || scamSnifferDB.data[key].includes(to.toLowerCase())
        );
        let _scamAddresses = [];
        if (toType === AddressType.ScamAddress) {
          _scamAddresses.push(to);
        }
        if (txFromType === AddressType.ScamAddress) {
          _scamAddresses.push(txFrom);
        }
        counters.detectedScamTransfers += 1;
        const anomalyScore = counters.detectedScamTransfers / counters.totalTransfers;
        findings.push(
          createTransferScamAlert(txFrom, from, to, asset, _scamAddresses, scamDomains, anomalyScore, hash)
        );
      }

      if (
        [
          AddressType.LowNumTxsVerifiedContract,
          AddressType.LowNumTxsUnverifiedContract,
          AddressType.EoaWithLowNonce,
        ].includes(toType)
      ) {
        const suspiciousContractFound = Array.from(suspiciousContracts).find(
          (contract) => contract.address === to || contract.creator === to
        );
        if (suspiciousContractFound) {
          counters.detectedSuspiciousTransfers += 1;
          const anomalyScore = counters.detectedSuspiciousTransfers / counters.totalTransfers;
          findings.push(
            createTransferSuspiciousContractAlert(txFrom, from, to, asset, suspiciousContractFound, anomalyScore, hash)
          );
        }
        if ([AddressType.LowNumTxsVerifiedContract, AddressType.LowNumTxsUnverifiedContract].includes(toType)) {
          const toContractCreator = await getContractCreator(to, chainId);
          const toContractCreatorType = toContractCreator
            ? await getAddressType(
                toContractCreator,
                scamAddresses,
                cachedAddresses,
                provider,
                blockNumber,
                chainId,
                false
              )
            : undefined;
          if (toContractCreatorType === AddressType.ScamAddress) {
            const scamDomains = Object.keys(scamSnifferDB.data).filter((key) =>
              scamSnifferDB.data[key].includes(toContractCreator.toLowerCase())
            );
            if (scamDomains.length > 0) {
              counters.detectedScamCreatorTransfers += 1;
              const anomalyScore = counters.detectedScamCreatorTransfers / counters.totalTransfers;
              findings.push(
                createTransferScamCreatorAlert(
                  txFrom,
                  from,
                  to,
                  asset,
                  toContractCreator,
                  scamDomains,
                  anomalyScore,
                  hash
                )
              );
            }
          }
        }
      }

      // Check if we monitor the spender
      const spenderApprovals = approvals[txFrom];
      const spenderApprovalsInfoSeverity = approvalsInfoSeverity[txFrom];
      const spenderPermissions = permissions[txFrom];
      const spenderPermissionsInfoSeverity = permissionsInfoSeverity[txFrom];
      if (!spenderApprovals && !spenderApprovalsInfoSeverity && !spenderPermissions && !spenderPermissionsInfoSeverity)
        return;
      spenderPermissions?.forEach((permission) => {
        if (permission.asset === asset && permission.owner === from && permission.deadline > timestamp) {
          if (!permission.value || permission.value.toString() === value.toString()) {
            counters.detectedPermittedTransfers += 1;
            const anomalyScore = counters.detectedPermittedTransfers / counters.totalTransfers;
            findings.push(createPermitTransferAlert(txFrom, from, to, asset, value, anomalyScore, hash));
          }
        }
      });

      spenderPermissionsInfoSeverity?.forEach((permission) => {
        if (permission.asset === asset && permission.owner === from && permission.deadline > timestamp) {
          if (!permission.value || permission.value.toString() === value.toString()) {
            counters.detectedPermittedTransfersMedium += 1;
            const anomalyScore = counters.detectedPermittedTransfersMedium / counters.totalTransfers;
            findings.push(createPermitTransferMediumSeverityAlert(txFrom, from, to, asset, value, anomalyScore, hash));
          }
        }
      });

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
        if (!hasMonitoredApproval) return;

        // Initialize the transfers array for the spender if it doesn't exist
        if (!transfers[txFrom]) transfers[txFrom] = [];

        console.log("Detected possible malicious transfer of approved assets");
        console.log(`owner: ${from}`);
        console.log(`spender: ${txFrom}`);
        console.log(`asset: ${asset}`);

        // Update the transfers for the spender
        transfers[txFrom].push({
          asset,
          owner: from,
          hash,
          timestamp,
        });

        // Filter out old transfers
        transfers[txFrom] = transfers[txFrom].filter((a) => timestamp - a.timestamp < TIME_PERIOD);
        if (transfers[txFrom].length > transferCountThreshold) {
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
              if (!balance.eq(0)) return;
            } else {
              const balance = ethers.BigNumber.from(await getBalance(asset, from, provider, txEvent.blockNumber));
              if (!balance.eq(0)) return;
            }
          }
          counters.detectedTransfers += transfers[txFrom].length;
          let anomalyScore = counters.detectedTransfers / counters.totalTransfers;
          anomalyScore = Math.min(anomalyScore, 1);
          findings.push(createHighNumTransfersAlert(txFrom, transfers[txFrom], anomalyScore));
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

        if (!hasMonitoredApproval) return;

        // Initialize the transfers array for the spender if it doesn't exist
        if (!transfersLowSeverity[txFrom]) transfersLowSeverity[txFrom] = [];

        console.log("Detected possible malicious transfer of approved assets");
        console.log(`owner: ${from}`);
        console.log(`spender: ${txFrom}`);
        console.log(`asset: ${asset}`);

        // Update the transfers for the spender
        transfersLowSeverity[txFrom].push({
          asset,
          owner: from,
          hash,
          timestamp,
        });

        // Filter out old transfers
        transfersLowSeverity[txFrom] = transfersLowSeverity[txFrom].filter(
          (a) => timestamp - a.timestamp < TIME_PERIOD
        );

        if (transfersLowSeverity[txFrom].length > transferCountThreshold) {
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
              if (!balance.eq(0)) return;
            } else {
              const balance = ethers.BigNumber.from(await getBalance(asset, from, provider, txEvent.blockNumber));
              if (!balance.eq(0)) return;
            }
          }
          counters.detectedTransfersLow += transfersLowSeverity[txFrom].length;
          let anomalyScore = counters.detectedTransfersLow / counters.totalTransfers;
          anomalyScore = Math.min(anomalyScore, 1);
          findings.push(createHighNumTransfersLowSeverityAlert(txFrom, transfersLowSeverity[txFrom], anomalyScore));
        }
      }
    })
  );

  return findings;
};

let lastTimestamp = 0;
let init = false;
let suspiciousContracts = new Set();

const provideHandleBlock =
  (getSuspiciousContracts, persistenceHelper, databaseKeys, counters) => async (blockEvent) => {
    const { timestamp, number } = blockEvent.block;

    if (!init) {
      suspiciousContracts = await getSuspiciousContracts(chainId, number, init);
    } else {
      let newSuspiciousContracts;
      try {
        newSuspiciousContracts = await getSuspiciousContracts(chainId, number, init);
      } catch {
        newSuspiciousContracts = new Set();
      }

      newSuspiciousContracts.forEach((contract) => suspiciousContracts.add(contract));
    }
    init = true;

    // console.log("transfers size:", Buffer.from(JSON.stringify(transfers)).length);
    // console.log("transfersLowSeverity size:", Buffer.from(JSON.stringify(transfersLowSeverity)).length);
    // console.log("approvals size:", Buffer.from(JSON.stringify(approvals)).length);
    // console.log("approvalsERC20 size:", Buffer.from(JSON.stringify(approvalsERC20)).length);
    // console.log("approvalsERC721 size:", Buffer.from(JSON.stringify(approvalsERC721)).length);

    const scamSnifferResponse = await axios.get(
      "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json"
    );
    scamAddresses = scamSnifferResponse.data;
    // Convert to checksum addresses
    scamAddresses = scamAddresses.map((address) => ethers.utils.getAddress(address));

    if (number % 240 === 0) {
      for (const key in counters) {
        await persistenceHelper.persist(counters[key], databaseKeys[key]);
      }
    }

    // Clean the data every timePeriodDays
    if (timestamp - lastTimestamp > TIME_PERIOD) {
      console.log("Cleaning");
      console.log(`Approvals before: ${Object.keys(approvals).length}`);
      console.log(`Approvals ERC20 before: ${Object.keys(approvalsERC20).length}`);
      console.log(`Approvals ERC721 before: ${Object.keys(approvalsERC721).length}`);
      console.log(`ApprovalsForAll ERC721 before: ${Object.keys(approvalsForAll721).length}`);
      console.log(`ApprovalsForAll ERC1155 before: ${Object.keys(approvalsForAll1155).length}`);
      console.log(`Permissions before: ${Object.keys(permissions).length}`);
      console.log(`Transfers before: ${Object.keys(transfers).length}`);
      console.log(`Approvals Info Severity before: ${Object.keys(approvalsInfoSeverity).length}`);
      console.log(`Approvals ERC20 Info Severity before: ${Object.keys(approvalsERC20InfoSeverity).length}`);
      console.log(`Approvals ERC721 Info Severity before: ${Object.keys(approvalsERC721InfoSeverity).length}`);
      console.log(`ApprovalsForAll ERC721 Info Severity before: ${Object.keys(approvalsForAll721InfoSeverity).length}`);
      console.log(
        `ApprovalsForAll ERC1155 Info Severity before: ${Object.keys(approvalsForAll1155InfoSeverity).length}`
      );
      console.log(`Permissions Info Severity before: ${Object.keys(permissionsInfoSeverity).length}`);
      console.log(`Transfers Low Severity before: ${Object.keys(transfersLowSeverity).length}`);

      Object.entries(approvals).forEach(([spender, data]) => {
        const { length } = data;
        // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
        if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
          delete approvals[spender];
        }
      });

      Object.entries(approvalsERC20).forEach(([spender, data]) => {
        const { length } = data;
        // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
        if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
          delete approvalsERC20[spender];
        }
      });

      Object.entries(approvalsERC721).forEach(([spender, data]) => {
        const { length } = data;
        // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
        if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
          delete approvalsERC721[spender];
        }
      });

      Object.entries(approvalsForAll721).forEach(([spender, data]) => {
        const { length } = data;
        // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
        if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
          delete approvalsForAll721[spender];
        }
      });

      Object.entries(approvalsForAll1155).forEach(([spender, data]) => {
        const { length } = data;
        // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
        if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
          delete approvalsForAll1155[spender];
        }
      });

      Object.keys(permissions).forEach((spender) => {
        permissions[spender] = permissions[spender].filter((entry) => entry.deadline > timestamp);
        if (!(permissions[spender].length > 0)) {
          delete permissions[spender];
        }
      });

      Object.entries(transfers).forEach(([spender, data]) => {
        const { length } = data;
        // Clear the transfers if the last transfer from a spender is more than timePeriodDays ago
        if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
          delete transfers[spender];
        }
      });

      Object.entries(approvalsInfoSeverity).forEach(([spender, data]) => {
        const { length } = data;
        // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
        if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
          delete approvalsInfoSeverity[spender];
        }
      });

      Object.entries(approvalsERC20InfoSeverity).forEach(([spender, data]) => {
        const { length } = data;
        // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
        if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
          delete approvalsERC20InfoSeverity[spender];
        }
      });

      Object.entries(approvalsERC721InfoSeverity).forEach(([spender, data]) => {
        const { length } = data;
        // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
        if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
          delete approvalsERC721InfoSeverity[spender];
        }
      });

      Object.entries(approvalsForAll721InfoSeverity).forEach(([spender, data]) => {
        const { length } = data;
        // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
        if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
          delete approvalsForAll721InfoSeverity[spender];
        }
      });

      Object.entries(approvalsForAll1155InfoSeverity).forEach(([spender, data]) => {
        const { length } = data;
        // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
        if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
          delete approvalsForAll1155InfoSeverity[spender];
        }
      });

      Object.keys(permissionsInfoSeverity).forEach((spender) => {
        permissionsInfoSeverity[spender] = permissionsInfoSeverity[spender].filter(
          (entry) => entry.deadline > timestamp
        );
        if (!(permissionsInfoSeverity[spender].length > 0)) {
          delete permissionsInfoSeverity[spender];
        }
      });

      Object.entries(transfersLowSeverity).forEach(([spender, data]) => {
        const { length } = data;
        // Clear the transfers if the last transfer from a spender is more than timePeriodDays ago
        if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
          delete transfersLowSeverity[spender];
        }
      });

      console.log(`Approvals after: ${Object.keys(approvals).length}`);
      console.log(`Approvals ERC20 after: ${Object.keys(approvalsERC20).length}`);
      console.log(`Approvals ERC721 after: ${Object.keys(approvalsERC721).length}`);
      console.log(`ApprovalsForAll ERC721 after: ${Object.keys(approvalsForAll721).length}`);
      console.log(`ApprovalsForAll ERC1155 after: ${Object.keys(approvalsForAll1155).length}`);
      console.log(`Permissions after: ${Object.keys(permissions).length}`);
      console.log(`Transfers after: ${Object.keys(transfers).length}`);
      console.log(`Approvals Info Severity after: ${Object.keys(approvalsInfoSeverity).length}`);
      console.log(`Approvals ERC20 Info Severity after: ${Object.keys(approvalsERC20InfoSeverity).length}`);
      console.log(`Approvals ERC721 Info Severity after: ${Object.keys(approvalsERC721InfoSeverity).length}`);
      console.log(`ApprovalsForAll ERC721 Info Severity after: ${Object.keys(approvalsForAll721InfoSeverity).length}`);
      console.log(
        `ApprovalsForAll ERC1155 Info Severity after: ${Object.keys(approvalsForAll1155InfoSeverity).length}`
      );
      console.log(`Permissions Info Severity after: ${Object.keys(permissionsInfoSeverity).length}`);
      console.log(`Transfers Low Severity after: ${Object.keys(transfersLowSeverity).length}`);

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
  initialize: provideInitialize(getEthersProvider(), new PersistenceHelper(DATABASE_URL), DATABASE_KEYS, counters),
  provideInitialize,
  provideHandleTransaction,
  handleTransaction: provideHandleTransaction(getEthersProvider(), counters, new PersistenceHelper(DATABASE_URL)),
  provideHandleBlock,
  handleBlock: provideHandleBlock(getSuspiciousContracts, new PersistenceHelper(DATABASE_URL), DATABASE_KEYS, counters),
  getApprovals: () => approvals, // Exported for unit tests
  getERC20Approvals: () => approvalsERC20, // Exported for unit tests
  getERC721Approvals: () => approvalsERC721, // Exported for unit tests
  getERC721ApprovalsForAll: () => approvalsForAll721, // Exported for unit tests
  getERC1155ApprovalsForAll: () => approvalsForAll1155, // Exported for unit tests
  getPermissions: () => permissions, // Exported for unit tests
  getTransfers: () => transfers, // Exported for unit tests
  getApprovalsInfoSeverity: () => approvalsInfoSeverity, // Exported for unit tests
  getERC20ApprovalsInfoSeverity: () => approvalsERC20InfoSeverity, // Exported for unit tests
  getERC721ApprovalsInfoSeverity: () => approvalsERC721InfoSeverity, // Exported for unit tests
  getERC721ApprovalsForAllInfoSeverity: () => approvalsForAll721InfoSeverity, // Exported for unit tests
  getERC1155ApprovalsForAllInfoSeverity: () => approvalsForAll1155InfoSeverity, // Exported for unit tests
  getPermissionsInfoSeverity: () => permissionsInfoSeverity, // Exported for unit tests
  getTransfersLowSeverity: () => transfersLowSeverity, // Exported for unit tests
  getCachedAddresses: () => cachedAddresses, // Exported for unit tests,
  getCachedERC1155Tokens: () => cachedERC1155Tokens, // Exported for unit tests,
  getSuspiciousContracts: () => suspiciousContracts, // Exported for unit tests
  resetLastTimestamp: () => {
    lastTimestamp = 0;
  },
  resetLastBlock: () => {
    lastBlock = 0;
  },
  resetInit: () => {
    init = false;
  },
};

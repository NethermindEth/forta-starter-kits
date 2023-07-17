const { ethers } = require("forta-agent");
const { ScanCountType } = require("bot-alert-rate");
const {
  createHighNumTransfersAlert,
  createHighNumTransfersLowSeverityAlert,
  createPigButcheringAlert,
  createPermitTransferAlert,
  createPermitTransferMediumSeverityAlert,
  createTransferScamAlert,
  createTransferSuspiciousContractAlert,
  hasTransferredNonStablecoins,
  getLabel,
  getInitialERC20Funder,
  getBalance,
  getERC1155Balance,
} = require("./helper");
const { transferCountThreshold, pigButcheringTransferCountThreshold } = require("../bot-config.json");
const {
  TIME_PERIOD,
  ADDRESS_ZERO,
  UNISWAP_ROUTER_ADDRESSES,
  STABLECOINS,
  transferFromSig,
  CEX_ADDRESSES,
  BOT_ID,
} = require("./utils");
const AddressType = require("./address-type");

const transfersHandletransaction = async (
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
) => {
  const { hash, blockNumber, timestamp } = txEvent;
  const txFrom = ethers.utils.getAddress(txEvent.from);

  for (const event of transferEvents) {
    counters.totalTransfers += 1;
    const asset = event.address;
    const { from, to, value, values, tokenId, tokenIds } = event.args;

    // Filter out direct transfers, mints and burns
    if (from === txFrom || from === ADDRESS_ZERO || to === ADDRESS_ZERO) {
      continue;
    }

    let id = tokenId || tokenIds;

    // Pig Butchering logic
    if (txEvent.transaction.data.startsWith(transferFromSig) && STABLECOINS.includes(asset)) {
      const isOwnerAlreadyCounted = objects.pigButcheringTransfers[to]?.some(
        (a) => a.owner === from && a.asset === asset
      );
      if (isOwnerAlreadyCounted) continue;
      if (!(await hasTransferredNonStablecoins(txFrom, chainId))) {
        const label = await getLabel(txFrom);
        if (!label || ["xploit", "hish", "heist"].some((keyword) => label.includes(keyword))) {
          if (ethers.BigNumber.from(value).gt(ethers.BigNumber.from(0)) && (await provider.getCode(from)) === "0x") {
            const balanceAfter = ethers.BigNumber.from(await getBalance(asset, from, provider, blockNumber));
            const balanceBefore = balanceAfter.add(ethers.BigNumber.from(value));
            if (balanceAfter.lt(balanceBefore.div(100)) && (await provider.getTransactionCount(from)) < 3) {
              const initialFunder = await getInitialERC20Funder(from, asset, chainId);
              if (CEX_ADDRESSES.includes(initialFunder)) {
                // Initialize the transfers array for the receiver if it doesn't exist
                if (!objects.pigButcheringTransfers[to]) objects.pigButcheringTransfers[to] = [];

                console.log("Detected possible malicious pig butchering transfer");
                console.log(`owner: ${from}`);
                console.log(`spender: ${txFrom}`);
                console.log(`receiver: ${to}`);
                console.log(`asset: ${asset}`);

                // Update the transfers for the spender
                objects.pigButcheringTransfers[to].push({
                  asset,
                  initiator: txFrom,
                  owner: from,
                  hash,
                  timestamp,
                });

                // Filter out old transfers
                objects.pigButcheringTransfers[to] = objects.pigButcheringTransfers[to].filter(
                  (a) => timestamp - a.timestamp < TIME_PERIOD
                );
                if (objects.pigButcheringTransfers[to].length > pigButcheringTransferCountThreshold) {
                  const anomalyScore = await calculateAlertRate(
                    chainId,
                    BOT_ID,
                    "ICE-PHISHING-PIG-BUTCHERING",
                    isRelevantChain ? ScanCountType.CustomScanCount : ScanCountType.ErcTransferCount,
                    counters.totalTransfers
                  );
                  findings.push(createPigButcheringAlert(to, objects.pigButcheringTransfers[to], hash, anomalyScore));
                  objects.pigButcheringTransfers[to] = [];
                  await persistenceHelper.persist(objects, databaseObjectsKey.key);
                }
              }
            }
          }
        }
      }
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
        createTransferScamAlert(txFrom, from, to, asset, id, _scamAddresses, scamDomains, anomalyScore, hash)
      );
    }

    const suspiciousContractFound = Array.from(suspiciousContracts).find(
      (contract) => contract.address === to || contract.creator === to
    );
    if (suspiciousContractFound && !UNISWAP_ROUTER_ADDRESSES.includes(txEvent.to)) {
      const anomalyScore = await calculateAlertRate(
        chainId,
        BOT_ID,
        "ICE-PHISHING-SUSPICIOUS-TRANSFER",
        isRelevantChain ? ScanCountType.CustomScanCount : ScanCountType.ErcTransferCount,
        counters.totalTransfers
      );
      findings.push(
        createTransferSuspiciousContractAlert(txFrom, from, to, asset, id, suspiciousContractFound, anomalyScore, hash)
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
      if (!objects.transfers[txFrom].some((obj) => obj.owner === from && obj.asset === asset)) {
        if (!id) id = "";
        objects.transfers[txFrom].push({
          asset,
          id,
          owner: from,
          hash,
          timestamp,
        });
      }

      // Filter out old transfers
      objects.transfers[txFrom] = objects.transfers[txFrom].filter((a) => timestamp - a.timestamp < TIME_PERIOD);
      if (objects.transfers[txFrom].length > transferCountThreshold) {
        if (value || (values && values.length > 0)) {
          if (tokenIds) {
            tokenIds.forEach(async (tokenId) => {
              const balance = ethers.BigNumber.from(
                await getERC1155Balance(asset, tokenId, from, provider, blockNumber)
              );
              if (!balance.eq(0)) return;
            });
          } else if (tokenId) {
            const balance = ethers.BigNumber.from(await getERC1155Balance(asset, tokenId, from, provider, blockNumber));
            if (!balance.eq(0)) continue;
          } else {
            const balance = ethers.BigNumber.from(await getBalance(asset, from, provider, blockNumber));
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
      if (!objects.transfersLowSeverity[txFrom].some((obj) => obj.owner === from && obj.asset === asset)) {
        if (!id) id = "";
        objects.transfersLowSeverity[txFrom].push({
          asset,
          id,
          owner: from,
          hash,
          timestamp,
        });
      }

      // Filter out old transfers
      objects.transfersLowSeverity[txFrom] = objects.transfersLowSeverity[txFrom].filter(
        (a) => timestamp - a.timestamp < TIME_PERIOD
      );

      if (objects.transfersLowSeverity[txFrom].length > transferCountThreshold) {
        if (value || (values && values.length > 0)) {
          if (tokenIds) {
            tokenIds.forEach(async (tokenId) => {
              const balance = ethers.BigNumber.from(
                await getERC1155Balance(asset, tokenId, from, provider, blockNumber)
              );
              if (!balance.eq(0)) return;
            });
          } else if (tokenId) {
            const balance = ethers.BigNumber.from(await getERC1155Balance(asset, tokenId, from, provider, blockNumber));
            if (!balance.eq(0)) continue;
          } else {
            const balance = ethers.BigNumber.from(await getBalance(asset, from, provider, blockNumber));
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
};

module.exports = {
  transfersHandletransaction,
};

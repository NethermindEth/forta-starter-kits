const { ethers } = require("forta-agent");
const { ScanCountType } = require("bot-alert-rate");

const {
  createHighNumApprovalsAlertERC20,
  createHighNumApprovalsInfoAlertERC20,
  createHighNumApprovalsAlertERC721,
  createHighNumApprovalsInfoAlertERC721,
  createApprovalForAllAlertERC721,
  createApprovalForAllInfoAlertERC721,
  createApprovalForAllAlertERC1155,
  createApprovalForAllInfoAlertERC1155,
  createApprovalScamAlert,
  createApprovalScamCreatorAlert,
  createApprovalSuspiciousContractAlert,
  getAddressType,
  getContractCreator,
  haveInteractedMoreThanOnce,
} = require("./helper");
const { approveCountThreshold, approveForAllCountThreshold, maxAddressAlertsPerPeriod } = require("../bot-config.json");
const { TIME_PERIOD, ADDRESS_ZERO, IGNORED_ADDRESSES, safeBatchTransferFrom1155Sig, BOT_ID } = require("./utils");
const AddressType = require("./address-type");

const approvalsHandleTransaction = async (
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
) => {
  const { hash, timestamp, blockNumber } = txEvent;
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
      txEvent.blockNumber,
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
          if (!objects.approvalsForAll1155InfoSeverity[spender]) objects.approvalsForAll1155InfoSeverity[spender] = [];
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
        const suspiciousContractFound = Array.from(suspiciousContracts).find(
          (contract) => contract.address === spender || contract.creator === spender
        );
        if (suspiciousContractFound) {
          const anomalyScore = await calculateAlertRate(
            chainId,
            BOT_ID,
            "ICE-PHISHING-SUSPICIOUS-APPROVAL",
            isRelevantChain ? ScanCountType.CustomScanCount : ScanCountType.ErcApprovalCount,
            counters.totalApprovals
          );
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
        let haveInteractedAgain = true;
        if (spenderType === AddressType.EoaWithHighNonce) {
          let assetOwnerArray = objects.approvalsERC20InfoSeverity[spender].map((entry) => [entry.asset, entry.owner]);
          haveInteractedAgain = await haveInteractedMoreThanOnce(spender, assetOwnerArray, chainId);
          if (haveInteractedAgain) {
            objects.approvalsERC20InfoSeverity[spender] = [];
          }
        }
        if (spenderType === AddressType.LowNumTxsVerifiedContract || !haveInteractedAgain) {
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
        let haveInteractedAgain = true;
        if (spenderType !== AddressType.LowNumTxsUnverifiedContract) {
          let assetOwnerArray = objects.approvalsERC20[spender].map((entry) => [entry.asset, entry.owner]);
          haveInteractedAgain = await haveInteractedMoreThanOnce(spender, assetOwnerArray, chainId);
          if (haveInteractedAgain) {
            objects.approvalsERC20[spender] = [];
          }
        }
        if (spenderType === AddressType.LowNumTxsUnverifiedContract || !haveInteractedAgain) {
          const anomalyScore = await calculateAlertRate(
            chainId,
            BOT_ID,
            "ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS",
            ScanCountType.CustomScanCount,
            counters.totalERC20Approvals
          );
          findings.push(createHighNumApprovalsAlertERC20(spender, objects.approvals[spender], anomalyScore));
        }
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
};

module.exports = {
  approvalsHandleTransaction,
};

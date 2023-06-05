const { Finding, FindingSeverity, FindingType, ethers, getAlerts, Label, EntityType } = require("forta-agent");
const { default: axios } = require("axios");
const LRU = require("lru-cache");
const { nonceThreshold, contractTxsThreshold, verifiedContractTxsThreshold } = require("../bot-config.json");
const { etherscanApis } = require("./config");
const { keys } = require("./keys");
const { MALICIOUS_SMART_CONTRACT_ML_BOT_V2_ID, ERC_20_721_INTERFACE, ERC_1155_INTERFACE } = require("./utils");
const AddressType = require("./address-type");

// Computes the data needed for an alert
function getEventInformation(eventsArray) {
  const { length } = eventsArray;
  const firstTxHash = eventsArray[0].hash;
  const lastTxHash = eventsArray[length - 1].hash;

  // Remove duplicates
  const assets = [...new Set(eventsArray.map((e) => e.asset))];
  const accounts = [...new Set(eventsArray.map((e) => e.owner))];

  const days = Math.ceil((eventsArray[length - 1].timestamp - eventsArray[0].timestamp) / 86400);

  return {
    firstTxHash,
    lastTxHash,
    assets,
    accounts,
    days,
  };
}

function createHighNumApprovalsAlertERC20(spender, approvalsArray, anomalyScore) {
  const { firstTxHash, lastTxHash, assets, accounts, days } = getEventInformation(approvalsArray);
  return Finding.fromObject({
    name: "High number of accounts granted approvals for ERC-20 tokens",
    description: `${spender} obtained transfer approval for ${assets.length} ERC-20 tokens by ${accounts.length} accounts over period of ${days} days.`,
    alertId: "ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS",
    severity: FindingSeverity.Low,
    type: FindingType.Suspicious,
    metadata: {
      firstTxHash,
      lastTxHash,
      anomalyScore: anomalyScore.toString(),
    },
    addresses: assets,
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Attacker",
        confidence: 0.3,
      }),
      Label.fromObject({
        entity: firstTxHash,
        entityType: EntityType.Transaction,
        label: "Approval",
        confidence: 1,
      }),
      Label.fromObject({
        entity: lastTxHash,
        entityType: EntityType.Transaction,
        label: "Approval",
        confidence: 1,
      }),
    ],
  });
}

function createHighNumApprovalsInfoAlertERC20(spender, approvalsArray, anomalyScore) {
  const { firstTxHash, lastTxHash, assets, accounts, days } = getEventInformation(approvalsArray);
  return Finding.fromObject({
    name: "High number of accounts granted approvals for ERC-20 tokens",
    description: `${spender} obtained transfer approval for ${assets.length} ERC-20 tokens by ${accounts.length} accounts over period of ${days} days.`,
    alertId: "ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS-INFO",
    severity: FindingSeverity.Info,
    type: FindingType.Info,
    metadata: {
      firstTxHash,
      lastTxHash,
      anomalyScore: anomalyScore.toString(),
    },
    addresses: assets,
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Attacker",
        confidence: 0.25,
      }),
      Label.fromObject({
        entity: firstTxHash,
        entityType: EntityType.Transaction,
        label: "Approval",
        confidence: 1,
      }),
      Label.fromObject({
        entity: lastTxHash,
        entityType: EntityType.Transaction,
        label: "Approval",
        confidence: 1,
      }),
    ],
  });
}

function createHighNumApprovalsAlertERC721(spender, approvalsArray, anomalyScore) {
  const { firstTxHash, lastTxHash, assets, accounts, days } = getEventInformation(approvalsArray);
  return Finding.fromObject({
    name: "High number of accounts granted approvals for ERC-721 tokens",
    description: `${spender} obtained transfer approval for ${assets.length} ERC-721 tokens by ${accounts.length} accounts over period of ${days} days.`,
    alertId: "ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS",
    severity: FindingSeverity.Low,
    type: FindingType.Suspicious,
    metadata: {
      firstTxHash,
      lastTxHash,
      anomalyScore: anomalyScore.toString(),
    },
    addresses: assets,
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Attacker",
        confidence: 0.3,
      }),
      Label.fromObject({
        entity: firstTxHash,
        entityType: EntityType.Transaction,
        label: "Approval",
        confidence: 1,
      }),
      Label.fromObject({
        entity: lastTxHash,
        entityType: EntityType.Transaction,
        label: "Approval",
        confidence: 1,
      }),
    ],
  });
}

function createHighNumApprovalsInfoAlertERC721(spender, approvalsArray, anomalyScore) {
  const { firstTxHash, lastTxHash, assets, accounts, days } = getEventInformation(approvalsArray);
  return Finding.fromObject({
    name: "High number of accounts granted approvals for ERC-721 tokens",
    description: `${spender} obtained transfer approval for ${assets.length} ERC-721 tokens by ${accounts.length} accounts over period of ${days} days.`,
    alertId: "ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS-INFO",
    severity: FindingSeverity.Info,
    type: FindingType.Info,
    metadata: {
      firstTxHash,
      lastTxHash,
      anomalyScore: anomalyScore.toString(),
    },
    addresses: assets,
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Attacker",
        confidence: 0.25,
      }),
      Label.fromObject({
        entity: firstTxHash,
        entityType: EntityType.Transaction,
        label: "Approval",
        confidence: 1,
      }),
      Label.fromObject({
        entity: lastTxHash,
        entityType: EntityType.Transaction,
        label: "Approval",
        confidence: 1,
      }),
    ],
  });
}

function createApprovalForAllAlertERC721(spender, owner, asset, anomalyScore, txHash) {
  return Finding.fromObject({
    name: "Account got approval for all ERC-721 tokens",
    description: `${spender} obtained transfer approval for all ERC-721 tokens from ${owner}`,
    alertId: "ICE-PHISHING-ERC721-APPROVAL-FOR-ALL",
    severity: FindingSeverity.Low,
    type: FindingType.Suspicious,
    metadata: {
      spender,
      owner,
      anomalyScore: anomalyScore.toString(),
    },
    addresses: [asset],
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Attacker",
        confidence: 0.2,
      }),
      Label.fromObject({
        entity: txHash,
        entityType: EntityType.Transaction,
        label: "Approval",
        confidence: 1,
      }),
    ],
  });
}

function createApprovalForAllInfoAlertERC721(spender, owner, asset, anomalyScore, txHash) {
  return Finding.fromObject({
    name: "Account got approval for all ERC-721 tokens",
    description: `${spender} obtained transfer approval for all ERC-721 tokens from ${owner}`,
    alertId: "ICE-PHISHING-ERC721-APPROVAL-FOR-ALL-INFO",
    severity: FindingSeverity.Info,
    type: FindingType.Info,
    metadata: {
      spender,
      owner,
      anomalyScore: anomalyScore.toString(),
    },
    addresses: [asset],
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Attacker",
        confidence: 0.15,
      }),
      Label.fromObject({
        entity: txHash,
        entityType: EntityType.Transaction,
        label: "Approval",
        confidence: 1,
      }),
    ],
  });
}

function createApprovalForAllAlertERC1155(spender, owner, asset, anomalyScore, txHash) {
  return Finding.fromObject({
    name: "Account got approval for all ERC-1155 tokens",
    description: `${spender} obtained transfer approval for all ERC-1155 tokens from ${owner}`,
    alertId: "ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL",
    severity: FindingSeverity.Low,
    type: FindingType.Suspicious,
    metadata: {
      spender,
      owner,
      anomalyScore: anomalyScore.toString(),
    },
    addresses: [asset],
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Attacker",
        confidence: 0.2,
      }),
      Label.fromObject({
        entity: txHash,
        entityType: EntityType.Transaction,
        label: "Approval",
        confidence: 1,
      }),
    ],
  });
}

function createApprovalForAllInfoAlertERC1155(spender, owner, asset, anomalyScore, txHash) {
  return Finding.fromObject({
    name: "Account got approval for all ERC-1155 tokens",
    description: `${spender} obtained transfer approval for all ERC-1155 tokens from ${owner}`,
    alertId: "ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL-INFO",
    severity: FindingSeverity.Info,
    type: FindingType.Info,
    metadata: {
      spender,
      owner,
      anomalyScore: anomalyScore.toString(),
    },
    addresses: [asset],
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Attacker",
        confidence: 0.15,
      }),
      Label.fromObject({
        entity: txHash,
        entityType: EntityType.Transaction,
        label: "Approval",
        confidence: 1,
      }),
    ],
  });
}

function createPermitAlert(msgSender, spender, owner, asset, anomalyScore, txHash) {
  return Finding.fromObject({
    name: "Account got permission for ERC-20 tokens",
    description: `${msgSender} gave permission to ${spender} for ${owner}'s ERC-20 tokens`,
    alertId: "ICE-PHISHING-ERC20-PERMIT",
    severity: FindingSeverity.Low,
    type: FindingType.Suspicious,
    metadata: {
      msgSender,
      spender,
      owner,
      anomalyScore: anomalyScore.toString(),
    },
    addresses: [asset],
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Attacker",
        confidence: 0.3,
      }),
      Label.fromObject({
        entity: txHash,
        entityType: EntityType.Transaction,
        label: "Permit",
        confidence: 1,
      }),
    ],
  });
}

function createPermitInfoAlert(msgSender, spender, owner, asset, anomalyScore, txHash) {
  return Finding.fromObject({
    name: "Account got permission for ERC-20 tokens",
    description: `${msgSender} gave permission to ${spender} for ${owner}'s ERC-20 tokens`,
    alertId: "ICE-PHISHING-ERC20-PERMIT-INFO",
    severity: FindingSeverity.Info,
    type: FindingType.Info,
    metadata: {
      msgSender,
      spender,
      owner,
      anomalyScore: anomalyScore.toString(),
    },
    addresses: [asset],
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Attacker",
        confidence: 0.2,
      }),
      Label.fromObject({
        entity: txHash,
        entityType: EntityType.Transaction,
        label: "Permit",
        confidence: 1,
      }),
    ],
  });
}

function createPermitScamAlert(msgSender, spender, owner, asset, scamAddresses, scamDomains, anomalyScore, txHash) {
  let labels = [];
  scamAddresses.map((scamAddress) => {
    labels.push(
      Label.fromObject({
        entity: scamAddress,
        entityType: EntityType.Address,
        label: "Attacker",
        confidence: 0.9,
      })
    );
  });
  labels.push(
    Label.fromObject({
      entity: txHash,
      entityType: EntityType.Transaction,
      label: "Permit",
      confidence: 1,
    })
  );
  return Finding.fromObject({
    name: "Known scam address was involved in an ERC-20 permission",
    description: `${msgSender} gave permission to ${spender} for ${owner}'s ERC-20 tokens`,
    alertId: "ICE-PHISHING-ERC20-SCAM-PERMIT",
    severity: FindingSeverity.High,
    type: FindingType.Suspicious,
    metadata: {
      scamAddresses,
      scamDomains,
      msgSender,
      spender,
      owner,
      anomalyScore: anomalyScore.toString(),
    },
    addresses: [asset],
    labels: labels,
  });
}

function createPermitScamCreatorAlert(
  msgSender,
  spender,
  owner,
  asset,
  scamAddress,
  scamDomains,
  anomalyScore,
  txHash
) {
  return Finding.fromObject({
    name: "Contract created by a known scam address was involved in an ERC-20 permission",
    description: `${msgSender} gave permission to ${spender} for ${owner}'s ERC-20 tokens`,
    alertId: "ICE-PHISHING-ERC20-SCAM-CREATOR-PERMIT",
    severity: FindingSeverity.High,
    type: FindingType.Suspicious,
    metadata: {
      scamAddress,
      scamDomains,
      msgSender,
      spender,
      owner,
      anomalyScore: anomalyScore.toString(),
    },
    addresses: [asset],
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Attacker",
        confidence: 0.9,
      }),
      Label.fromObject({
        entity: txHash,
        entityType: EntityType.Transaction,
        label: "Permit",
        confidence: 1,
      }),
    ],
  });
}

// function createPermitSuspiciousContractAlert(
//   msgSender,
//   spender,
//   owner,
//   asset,
//   suspiciousContract,
//   anomalyScore,
//   txHash
// ) {
//   return Finding.fromObject({
//     name: "Suspicious contract (creator) was involved in an ERC-20 permission",
//     description: `${msgSender} gave permission to ${spender} for ${owner}'s ERC-20 tokens`,
//     alertId: "ICE-PHISHING-ERC20-SUSPICIOUS-PERMIT",
//     severity: FindingSeverity.Medium,
//     type: FindingType.Suspicious,
//     metadata: {
//       suspiciousContract: suspiciousContract.address,
//       suspiciousContractCreator: suspiciousContract.creator,
//       msgSender,
//       spender,
//       owner,
//       anomalyScore: anomalyScore.toString(),
//     },
//     addresses: [asset],
//     labels: [
//       Label.fromObject({
//         entity: spender,
//         entityType: EntityType.Address,
//         label: "Attacker",
//         confidence: 0.5,
//       }),
//       Label.fromObject({
//         entity: txHash,
//         entityType: EntityType.Transaction,
//         label: "Permit",
//         confidence: 1,
//       }),
//     ],
//   });
// }

function createApprovalScamAlert(scamSpender, owner, asset, scamDomains, anomalyScore, txHash) {
  return Finding.fromObject({
    name: "Known scam address got approval to spend assets",
    description: `Scam address ${scamSpender} got approval for ${owner}'s assets`,
    alertId: "ICE-PHISHING-SCAM-APPROVAL",
    severity: FindingSeverity.High,
    type: FindingType.Suspicious,
    metadata: {
      scamDomains,
      scamSpender,
      owner,
      anomalyScore: anomalyScore.toString(),
    },
    addresses: [asset],
    labels: [
      Label.fromObject({
        entity: scamSpender,
        entityType: EntityType.Address,
        label: "Attacker",
        confidence: 0.9,
      }),
      Label.fromObject({
        entity: txHash,
        entityType: EntityType.Transaction,
        label: "Approval",
        confidence: 1,
      }),
    ],
  });
}

// function createApprovalSuspiciousContractAlert(
//   suspiciousSpender,
//   owner,
//   asset,
//   contract,
//   creator,
//   anomalyScore,
//   txHash
// ) {
//   return Finding.fromObject({
//     name: "Suspicious contract (creator) got approval to spend assets",
//     description: `Suspicious address ${suspiciousSpender} got approval for ${owner}'s assets`,
//     alertId: "ICE-PHISHING-SUSPICIOUS-APPROVAL",
//     severity: FindingSeverity.Medium,
//     type: FindingType.Suspicious,
//     metadata: {
//       suspiciousSpender,
//       suspiciousContract: contract,
//       suspiciousContractCreator: creator,
//       owner,
//       anomalyScore: anomalyScore.toString(),
//     },
//     addresses: [asset],
//     labels: [
//       Label.fromObject({
//         entity: suspiciousSpender,
//         entityType: EntityType.Address,
//         label: "Attacker",
//         confidence: 0.5,
//       }),
//       Label.fromObject({
//         entity: txHash,
//         entityType: EntityType.Transaction,
//         label: "Approval",
//         confidence: 1,
//       }),
//     ],
//   });
// }

function createApprovalScamCreatorAlert(spender, scamCreator, owner, asset, scamDomains, anomalyScore, txHash) {
  return Finding.fromObject({
    name: "Contract, created by a known scam address, got approval to spend assets",
    description: `${spender}, created by the scam address ${scamCreator}, got approval for ${owner}'s assets`,
    alertId: "ICE-PHISHING-SCAM-CREATOR-APPROVAL",
    severity: FindingSeverity.High,
    type: FindingType.Suspicious,
    metadata: {
      scamDomains,
      scamCreator,
      spender,
      owner,
      anomalyScore: anomalyScore.toString(),
    },
    addresses: [asset],
    labels: [
      Label.fromObject({
        entity: scamCreator,
        entityType: EntityType.Address,
        label: "Attacker",
        confidence: 0.9,
      }),
      Label.fromObject({
        entity: txHash,
        entityType: EntityType.Transaction,
        label: "Approval",
        confidence: 1,
      }),
    ],
  });
}

function createTransferScamAlert(msgSender, owner, receiver, asset, scamAddresses, scamDomains, anomalyScore, txHash) {
  let labels = [];
  scamAddresses.map((scamAddress) => {
    labels.push(
      Label.fromObject({
        entity: scamAddress,
        entityType: EntityType.Address,
        label: "Attacker",
        confidence: 0.95,
      })
    );
  });
  labels.push(
    Label.fromObject({
      entity: txHash,
      entityType: EntityType.Transaction,
      label: "Transfer",
      confidence: 1,
    })
  );

  return Finding.fromObject({
    name: "Known scam address was involved in an asset transfer",
    description: `${msgSender} transferred assets from ${owner} to ${receiver}`,
    alertId: "ICE-PHISHING-SCAM-TRANSFER",
    severity: FindingSeverity.Critical,
    type: FindingType.Exploit,
    metadata: {
      scamAddresses,
      scamDomains,
      msgSender,
      owner,
      receiver,
      anomalyScore: anomalyScore.toString(),
    },
    addresses: [asset],
    labels: labels,
  });
}

function createHighNumTransfersAlert(spender, transfersArray, anomalyScore) {
  const { firstTxHash, lastTxHash, assets, accounts, days } = getEventInformation(transfersArray);
  return Finding.fromObject({
    name: "Previously approved assets transferred",
    description: `${spender} transferred ${assets.length} assets from ${accounts.length} accounts over period of ${days} days.`,
    alertId: "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS",
    severity: FindingSeverity.High,
    type: FindingType.Exploit,
    metadata: {
      firstTxHash,
      lastTxHash,
      anomalyScore: anomalyScore.toString(),
    },
    addresses: assets,
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Attacker",
        confidence: 0.4,
      }),
      Label.fromObject({
        entity: firstTxHash,
        entityType: EntityType.Transaction,
        label: "Transfer",
        confidence: 1,
      }),
      Label.fromObject({
        entity: lastTxHash,
        entityType: EntityType.Transaction,
        label: "Transfer",
        confidence: 1,
      }),
    ],
  });
}

function createHighNumTransfersLowSeverityAlert(spender, transfersArray, anomalyScore) {
  const { firstTxHash, lastTxHash, assets, accounts, days } = getEventInformation(transfersArray);
  return Finding.fromObject({
    name: "Previously approved assets transferred",
    description: `${spender} transferred ${assets.length} assets from ${accounts.length} accounts over period of ${days} days.`,
    alertId: "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS-LOW",
    severity: FindingSeverity.Low,
    type: FindingType.Suspicious,
    metadata: {
      firstTxHash,
      lastTxHash,
      anomalyScore: anomalyScore.toString(),
    },
    addresses: assets,
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Attacker",
        confidence: 0.25,
      }),
      Label.fromObject({
        entity: firstTxHash,
        entityType: EntityType.Transaction,
        label: "Transfer",
        confidence: 1,
      }),
      Label.fromObject({
        entity: lastTxHash,
        entityType: EntityType.Transaction,
        label: "Transfer",
        confidence: 1,
      }),
    ],
  });
}

function createPermitTransferAlert(spender, owner, receiver, asset, value, anomalyScore, txHash) {
  return Finding.fromObject({
    name: "Previously permitted assets transferred",
    description: `${spender} transferred ${value} tokens from ${owner} to ${receiver}`,
    alertId: "ICE-PHISHING-PERMITTED-ERC20-TRANSFER",
    severity: FindingSeverity.Critical,
    type: FindingType.Exploit,
    metadata: {
      spender,
      owner,
      receiver,
      anomalyScore: anomalyScore.toString(),
    },
    addresses: asset,
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Attacker",
        confidence: 0.4,
      }),
      Label.fromObject({
        entity: txHash,
        entityType: EntityType.Transaction,
        label: "Transfer",
        confidence: 1,
      }),
    ],
  });
}

function createPermitTransferMediumSeverityAlert(spender, owner, receiver, asset, value, anomalyScore, txHash) {
  return Finding.fromObject({
    name: "Previously permitted assets transferred",
    description: `${spender} transferred ${value} tokens from ${owner} to ${receiver}`,
    alertId: "ICE-PHISHING-PERMITTED-ERC20-TRANSFER-MEDIUM",
    severity: FindingSeverity.Medium,
    type: FindingType.Suspicious,
    metadata: {
      spender,
      owner,
      receiver,
      anomalyScore: anomalyScore.toString(),
    },
    addresses: asset,
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Attacker",
        confidence: 0.3,
      }),
      Label.fromObject({
        entity: txHash,
        entityType: EntityType.Transaction,
        label: "Transfer",
        confidence: 1,
      }),
    ],
  });
}

function createSweepTokenAlert(victim, attacker, asset, value, anomalyScore, txHash) {
  return Finding.fromObject({
    name: "Attacker stole funds through Router V3's pull and sweepTokens functions",
    description: `${attacker} received ${value} tokens (${asset}) from ${victim}`,
    alertId: "ICE-PHISHING-PULL-SWEEPTOKEN",
    severity: FindingSeverity.Critical,
    type: FindingType.Suspicious,
    metadata: {
      attacker,
      victim,
      anomalyScore: anomalyScore.toString(),
    },
    addresses: asset,
    labels: [
      Label.fromObject({
        entity: attacker,
        entityType: EntityType.Address,
        label: "Attacker",
        confidence: 0.8,
      }),
      Label.fromObject({
        entity: victim,
        entityType: EntityType.Address,
        label: "Victim",
        confidence: 0.8,
      }),
      Label.fromObject({
        entity: txHash,
        entityType: EntityType.Transaction,
        label: "Attack",
        confidence: 0.8,
      }),
    ],
  });
}

function createOpenseaAlert(victim, attacker, newImplementation, anomalyScore, txHash) {
  return Finding.fromObject({
    name: "Opensea proxy implementation changed to attacker's contract",
    description: `${victim} was tricked into upgrading their Opensea proxy implementation to ${newImplementation} created by ${attacker}`,
    alertId: "ICE-PHISHING-OPENSEA-PROXY-UPGRADE",
    severity: FindingSeverity.Critical,
    type: FindingType.Suspicious,
    metadata: {
      victim,
      attacker,
      newImplementation,
      anomalyScore: anomalyScore.toString(),
    },
    labels: [
      Label.fromObject({
        entity: attacker,
        entityType: EntityType.Address,
        label: "Attacker",
        confidence: 0.8,
      }),
      Label.fromObject({
        entity: victim,
        entityType: EntityType.Address,
        label: "Victim",
        confidence: 0.8,
      }),
      Label.fromObject({
        entity: txHash,
        entityType: EntityType.Transaction,
        label: "Attack",
        confidence: 0.8,
      }),
    ],
  });
}

function getBlockExplorerKey(chainId) {
  switch (chainId) {
    case 10:
      return keys.optimisticEtherscanApiKeys.length > 0
        ? keys.optimisticEtherscanApiKeys[Math.floor(Math.random() * keys.optimisticEtherscanApiKeys.length)]
        : "YourApiKeyToken";
    case 56:
      return keys.bscscanApiKeys.length > 0
        ? keys.bscscanApiKeys[Math.floor(Math.random() * keys.bscscanApiKeys.length)]
        : "YourApiKeyToken";
    case 137:
      return keys.polygonscanApiKeys.length > 0
        ? keys.polygonscanApiKeys[Math.floor(Math.random() * keys.polygonscanApiKeys.length)]
        : "YourApiKeyToken";
    case 250:
      return keys.fantomscanApiKeys.length > 0
        ? keys.fantomscanApiKeys[Math.floor(Math.random() * keys.fantomscanApiKeys.length)]
        : "YourApiKeyToken";
    case 42161:
      return keys.arbiscanApiKeys.length > 0
        ? keys.arbiscanApiKeys[Math.floor(Math.random() * keys.arbiscanApiKeys.length)]
        : "YourApiKeyToken";
    case 43114:
      return keys.snowtraceApiKeys.length > 0
        ? keys.snowtraceApiKeys[Math.floor(Math.random() * keys.snowtraceApiKeys.length)]
        : "YourApiKeyToken";
    default:
      return keys.etherscanApiKeys.length > 0
        ? keys.etherscanApiKeys[Math.floor(Math.random() * keys.etherscanApiKeys.length)]
        : "YourApiKeyToken";
  }
}

function getEtherscanContractUrl(address, chainId) {
  const { urlContract } = etherscanApis[Number(chainId)];
  const key = getBlockExplorerKey(Number(chainId));
  return `${urlContract}&address=${address}&apikey=${key}`;
}

function getEtherscanAddressUrl(address, chainId, offset) {
  const { urlAccount } = etherscanApis[Number(chainId)];
  const key = getBlockExplorerKey(Number(chainId));
  return `${urlAccount}&address=${address}&startblock=0&endblock=99999999&page=1&offset=${
    offset + 1
  }&sort=asc&apikey=${key}`;
}

function getEtherscanLogsUrl(address, blockNumber, chainId) {
  const { urlLogs } = etherscanApis[Number(chainId)];
  const key = getBlockExplorerKey(Number(chainId));
  return `${urlLogs}&address=${address}&fromBlock=0&toBlock=${blockNumber}&page=1&offset=5&sort=asc&apikey=${key}`;
}

async function isOpenseaProxy(address, blockNumber, chainId) {
  const url = getEtherscanLogsUrl(address, blockNumber - 1, chainId);

  let retries = 2;
  let result;
  for (let i = 0; i <= retries; i++) {
    try {
      result = await axios.get(url);
      // Handle successful response
      break; // Exit the loop if successful
    } catch {
      if (i === retries) {
        // Handle error after all retries
        throw new Error(`All retry attempts to call block explorer (URL: ${url}) failed`);
      } else {
        // Handle error and retry
        console.log(`Retry attempt ${i + 1} to call block explorer failed`);
        await new Promise((resolve) => setTimeout(resolve, 500));
      }
    }
  }

  const pastEvents = result.data.result;
  const isOpensea = pastEvents.some((event) => {
    return (
      event.topics[0] === "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b" &&
      event.topics[1] === "0x000000000000000000000000f9e266af4bca5890e2781812cc6a6e89495a79f2"
    );
  });

  return isOpensea;
}

async function getContractCreator(address, chainId) {
  const { urlContractCreation } = etherscanApis[Number(chainId)];
  const key = getBlockExplorerKey(Number(chainId));
  const url = `${urlContractCreation}&contractaddresses=${address}&apikey=${key}`;

  let retries = 2;
  let result;
  for (let i = 0; i <= retries; i++) {
    try {
      result = await axios.get(url);
      // Handle successful response
      break; // Exit the loop if successful
    } catch {
      if (i === retries) {
        // Handle error after all retries
        throw new Error(`All retry attempts to call block explorer (URL: ${url}) failed`);
      } else {
        // Handle error and retry
        console.log(`Retry attempt ${i + 1} to call block explorer failed`);
        await new Promise((resolve) => setTimeout(resolve, 500));
      }
    }
  }

  if (result.data.message.startsWith("NOTOK") || result.data.message.startsWith("No data found")) {
    console.log(`block explorer error occured; skipping check for ${address}`);
    return null;
  }
  const contractCreator = result.data.result[0].contractCreator;

  // E.g. contract 0x85149247691df622eaf1a8bd0cafd40bc45154a9 on Optimism returns "GENESIS" as the creator
  if (!contractCreator.startsWith("0x")) {
    console.log("Contract creator is not an address:", contractCreator);
    return null;
  } else {
    return contractCreator;
  }
}

async function getEoaType(address, provider, blockNumber) {
  let nonce;
  let tries = 0;
  const maxTries = 3;

  while (tries < maxTries) {
    try {
      nonce = await provider.getTransactionCount(address, blockNumber);
      break; // exit the loop if successful
    } catch (err) {
      tries++;
      if (tries === maxTries) {
        nonce = 0;
        console.log("Error on fetching the transaction count, setting the nonce to 0"); // re-throw the error if maximum tries reached
      }
      await new Promise((resolve) => setTimeout(resolve, 1000)); // wait for 1 second before retrying
    }
  }
  return nonce > nonceThreshold ? AddressType.EoaWithHighNonce : AddressType.EoaWithLowNonce;
}

async function getContractType(address, chainId) {
  let result;

  let retries = 2;
  for (let i = 0; i <= retries; i++) {
    try {
      result = await axios.get(getEtherscanContractUrl(address, chainId));
      // Handle successful response
      break; // Exit the loop if successful
    } catch {
      if (i === retries) {
        // Handle error after all retries
        throw new Error(
          `All retry attempts to call block explorer (URL: ${getEtherscanContractUrl(address, chainId)}) failed`
        );
      } else {
        // Handle error and retry
        console.log(`Retry attempt ${i + 1} to call block explorer failed`);
        await new Promise((resolve) => setTimeout(resolve, 500));
      }
    }
  }

  if (result.data.message.startsWith("NOTOK") && result.data.result !== "Contract source code not verified") {
    console.log(`block explorer error occured; skipping check for ${address}`);
    return null;
  }

  const isVerified = result.data.status === "1";
  const url = isVerified
    ? getEtherscanAddressUrl(address, chainId, verifiedContractTxsThreshold)
    : getEtherscanAddressUrl(address, chainId, contractTxsThreshold);
  for (let i = 0; i <= retries; i++) {
    try {
      result = await axios.get(url);
      break; // Exit the loop if successful
    } catch {
      if (i === retries) {
        // Handle error after all retries
        throw new Error(`All retry attempts to call block explorer failed`);
      } else {
        // Handle error and retry
        console.log(`Retry attempt ${i + 1} to call block explorer failed`);
        await new Promise((resolve) => setTimeout(resolve, 500));
      }
    }
  }

  if (result.data.message.startsWith("NOTOK") || result.data.message.startsWith("Query Timeout")) {
    console.log(`block explorer error occured; skipping check for ${address}`);
    return null;
  }

  if (isVerified) {
    const hasHighNumberOfTotalTxs = result.data.result.length > verifiedContractTxsThreshold;
    return hasHighNumberOfTotalTxs ? AddressType.HighNumTxsVerifiedContract : AddressType.LowNumTxsVerifiedContract;
  } else {
    const hasHighNumberOfTotalTxs = result.data.result.length > contractTxsThreshold;
    return hasHighNumberOfTotalTxs ? AddressType.HighNumTxsUnverifiedContract : AddressType.LowNumTxsUnverifiedContract;
  }
}

async function getAddressType(address, scamAddresses, cachedAddresses, provider, blockNumber, chainId, isOwner) {
  if (scamAddresses.includes(address)) {
    if (!cachedAddresses.has(address) || cachedAddresses.get(address) !== AddressType.ScamAddress) {
      cachedAddresses.set(address, AddressType.ScamAddress);
    }
    return AddressType.ScamAddress;
  }

  if (cachedAddresses.has(address)) {
    const type = cachedAddresses.get(address);

    // Don't update the cached address if
    // the check is for the owner
    // the type cannot be changed back
    // the type is unverified contract but with high number of txs indicating it will remain unverified
    // the address is ignored
    if (
      isOwner ||
      type === AddressType.EoaWithHighNonce ||
      type === AddressType.HighNumTxsVerifiedContract ||
      type === AddressType.HighNumTxsUnverifiedContract ||
      type.startsWith("Ignored")
    ) {
      return type;
    }

    const getTypeFn =
      type === AddressType.EoaWithLowNonce
        ? async () => getEoaType(address, provider, blockNumber)
        : async () => getContractType(address, chainId);
    const newType = await getTypeFn(address, blockNumber);

    if (newType && newType !== type) cachedAddresses.set(address, newType);
    return newType;
  }

  // If the address is not in the cache check if it is a contract
  let code;
  let tries = 0;
  const maxTries = 3;
  while (tries < maxTries) {
    try {
      code = await provider.getCode(address);
      break; // exit the loop if successful
    } catch (err) {
      tries++;
      if (tries === maxTries) {
        throw err; // re-throw the error if maximum tries reached
      }
      await new Promise((resolve) => setTimeout(resolve, 1000)); // wait for 1 second before retrying
    }
  }

  const isEoa = code === "0x";

  // Skip etherscan call and directly return unverified if checking for the owner
  if (isOwner && !isEoa) return AddressType.LowNumTxsUnverifiedContract;

  const getTypeFn = isEoa
    ? async () => getEoaType(address, provider, blockNumber)
    : async () => getContractType(address, chainId);
  const type = await getTypeFn(address, blockNumber);

  if (type) cachedAddresses.set(address, type);
  return type;
}

// async function getSuspiciousContracts(chainId, blockNumber, init) {
//   let contracts = [];
//   let startingCursor;

//   if (!init) {
//     const fortaResponse = await getAlerts({
//       botIds: [MALICIOUS_SMART_CONTRACT_ML_BOT_V2_ID],
//       alertId: "SUSPICIOUS-CONTRACT-CREATION",
//       chainId: chainId,
//       blockNumberRange: {
//         startBlockNumber: blockNumber - 20000,
//         endBlockNumber: blockNumber,
//       },
//       first: 5000,
//     });

//     fortaResponse.alerts.forEach((alert) => {
//       contracts.push({ address: alert.description.slice(-42), creator: alert.description.slice(0, 42) });
//     });

//     startingCursor = fortaResponse.pageInfo.endCursor;
//     while (startingCursor.blockNumber > 0) {
//       const fortaResponse = await getAlerts({
//         botIds: [MALICIOUS_SMART_CONTRACT_ML_BOT_V2_ID],
//         alertId: "SUSPICIOUS-CONTRACT-CREATION",
//         chainId: chainId,
//         blockNumberRange: {
//           startBlockNumber: blockNumber - 15000,
//           endBlockNumber: blockNumber,
//         },
//         first: 1000,
//         startingCursor: startingCursor,
//       });

//       fortaResponse.alerts.forEach((alert) => {
//         contracts.push({ address: alert.description.slice(-42), creator: alert.description.slice(0, 42) });
//       });

//       startingCursor = fortaResponse.pageInfo.endCursor;
//     }
//     contracts = contracts.map((contract) => {
//       return {
//         address: ethers.utils.getAddress(contract.address),
//         creator: ethers.utils.getAddress(contract.creator),
//       };
//     });

//     return new Set(contracts);
//   } else {
//     const fortaResponse = await getAlerts({
//       botIds: [MALICIOUS_SMART_CONTRACT_ML_BOT_V2_ID],
//       alertId: "SUSPICIOUS-CONTRACT-CREATION",
//       chainId: chainId,
//       blockNumberRange: {
//         startBlockNumber: blockNumber - 240,
//         endBlockNumber: blockNumber,
//       },
//       first: 1000,
//     });

//     fortaResponse.alerts.forEach((alert) => {
//       contracts.push({ address: alert.description.slice(-42), creator: alert.description.slice(0, 42) });
//     });
//     contracts = contracts.map((contract) => {
//       return {
//         address: ethers.utils.getAddress(contract.address),
//         creator: ethers.utils.getAddress(contract.creator),
//       };
//     });
//     return new Set(contracts);
//   }
// }

const cachedBalances = new LRU({ max: 100_000 });

async function getBalance(token, account, provider, blockNumber) {
  const key = `${account}-${token}-${blockNumber}`;
  if (cachedBalances.has(key)) return cachedBalances.get(key);
  const tokenContract = new ethers.Contract(token, ERC_20_721_INTERFACE, provider);
  const balance = await tokenContract.balanceOf(account, {
    blockTag: blockNumber,
  });
  cachedBalances.set(key, balance);
  return balance;
}

async function getERC1155Balance(token, id, account, provider, blockNumber) {
  const key = `${account}-${token} -${id}-${blockNumber}`;
  if (cachedBalances.has(key)) return cachedBalances.get(key);
  const tokenContract = new ethers.Contract(token, ERC_1155_INTERFACE, provider);
  const balance = await tokenContract.balanceOf(account, id, {
    blockTag: blockNumber,
  });
  cachedBalances.set(key, balance);
  return balance;
}

async function getTransactions(provider, blockNumber) {
  let retries = 2;
  for (let i = 0; i <= retries; i++) {
    try {
      const { transactions } = await provider.getBlockWithTransactions(blockNumber);
      return transactions; // Exit the loop if successful
    } catch {
      if (i === retries) {
        // Handle error after all retries
        throw new Error(`All retry attempts to fetch transactions failed`);
      } else {
        // Handle error and retry
        console.log(`Retry attempt ${i + 1} to fetch transactions failed`);
        await new Promise((resolve) => setTimeout(resolve, 500));
      }
    }
  }
}

function checkObjectSizeAndCleanup(obj) {
  // Flatten the object's values into an array of entries, and sort by timestamp
  const entries = Object.values(obj).flat();
  if (entries.length === 0) return;
  entries.sort((a, b) => a.timestamp - b.timestamp);

  // Delete half of the oldest entries
  const numEntriesToDelete = Math.ceil(entries.length / 2);
  for (let i = 0; i < numEntriesToDelete; i++) {
    const entryToDelete = entries[i];
    const key = Object.keys(obj).find((k) => obj[k].includes(entryToDelete));
    obj[key] = obj[key].filter((entry) => entry !== entryToDelete);
    if (obj[key].length === 0) {
      delete obj[key];
    }
  }
}

module.exports = {
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
  getEoaType,
  getContractCreator,
  // getSuspiciousContracts,
  getBalance,
  getERC1155Balance,
  getTransactions,
  isOpenseaProxy,
  checkObjectSizeAndCleanup,
};

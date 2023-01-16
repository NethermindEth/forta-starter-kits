const { Finding, FindingSeverity, FindingType, ethers, getAlerts, Label, EntityType } = require("forta-agent");
const { default: axios } = require("axios");
const LRU = require("lru-cache");
const { nonceThreshold, contractTxsThreshold, verifiedContractTxsThreshold } = require("../bot-config.json");
const { etherscanApis } = require("./config");
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
      anomalyScore: anomalyScore.toFixed(2),
    },
    addresses: assets,
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Ice Phishing Attacker",
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
      anomalyScore: anomalyScore.toFixed(2),
    },
    addresses: assets,
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Ice Phishing Attacker",
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
      anomalyScore: anomalyScore.toFixed(2),
    },
    addresses: assets,
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Ice Phishing Attacker",
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
      anomalyScore: anomalyScore.toFixed(2),
    },
    addresses: assets,
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Ice Phishing Attacker",
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
      anomalyScore: anomalyScore.toFixed(2),
    },
    addresses: [asset],
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Ice Phishing Attacker",
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
      anomalyScore: anomalyScore.toFixed(2),
    },
    addresses: [asset],
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Ice Phishing Attacker",
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
      anomalyScore: anomalyScore.toFixed(2),
    },
    addresses: [asset],
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Ice Phishing Attacker",
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
      anomalyScore: anomalyScore.toFixed(2),
    },
    addresses: [asset],
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Ice Phishing Attacker",
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
      anomalyScore: anomalyScore.toFixed(2),
    },
    addresses: [asset],
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Ice Phishing Attacker",
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
      anomalyScore: anomalyScore.toFixed(2),
    },
    addresses: [asset],
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Ice Phishing Attacker",
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
        label: "Ice Phishing Attacker",
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
      anomalyScore: anomalyScore.toFixed(2),
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
      anomalyScore: anomalyScore.toFixed(2),
    },
    addresses: [asset],
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Ice Phishing Attacker",
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

function createPermitSuspiciousContractAlert(
  msgSender,
  spender,
  owner,
  asset,
  suspiciousContract,
  anomalyScore,
  txHash
) {
  return Finding.fromObject({
    name: "Suspicious contract (creator) was involved in an ERC-20 permission",
    description: `${msgSender} gave permission to ${spender} for ${owner}'s ERC-20 tokens`,
    alertId: "ICE-PHISHING-ERC20-SUSPICIOUS-PERMIT",
    severity: FindingSeverity.Medium,
    type: FindingType.Suspicious,
    metadata: {
      suspiciousContract: suspiciousContract.address,
      suspiciousContractCreator: suspiciousContract.creator,
      msgSender,
      spender,
      owner,
      anomalyScore: anomalyScore.toFixed(2),
    },
    addresses: [asset],
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Ice Phishing Attacker",
        confidence: 0.5,
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
      anomalyScore: anomalyScore.toFixed(2),
    },
    addresses: [asset],
    labels: [
      Label.fromObject({
        entity: scamSpender,
        entityType: EntityType.Address,
        label: "Ice Phishing Attacker",
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

function createApprovalSuspiciousContractAlert(
  suspiciousSpender,
  owner,
  asset,
  contract,
  creator,
  anomalyScore,
  txHash
) {
  return Finding.fromObject({
    name: "Suspicious contract (creator) got approval to spend assets",
    description: `Suspicious address ${suspiciousSpender} got approval for ${owner}'s assets`,
    alertId: "ICE-PHISHING-SUSPICIOUS-APPROVAL",
    severity: FindingSeverity.Medium,
    type: FindingType.Suspicious,
    metadata: {
      suspiciousSpender,
      suspiciousContract: contract,
      suspiciousContractCreator: creator,
      owner,
      anomalyScore: anomalyScore.toFixed(2),
    },
    addresses: [asset],
    labels: [
      Label.fromObject({
        entity: suspiciousSpender,
        entityType: EntityType.Address,
        label: "Ice Phishing Attacker",
        confidence: 0.5,
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
      anomalyScore: anomalyScore.toFixed(2),
    },
    addresses: [asset],
    labels: [
      Label.fromObject({
        entity: scamCreator,
        entityType: EntityType.Address,
        label: "Ice Phishing Attacker",
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
        label: "Ice Phishing Attacker",
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
      anomalyScore: anomalyScore.toFixed(2),
    },
    addresses: [asset],
    labels: labels,
  });
}

function createTransferSuspiciousContractAlert(
  msgSender,
  owner,
  receiver,
  asset,
  suspiciousContract,
  anomalyScore,
  txHash
) {
  return Finding.fromObject({
    name: "Suspicious contract (creator) was involved in an asset transfer",
    description: `${msgSender} transferred assets from ${owner} to ${receiver}`,
    alertId: "ICE-PHISHING-SUSPICIOUS-TRANSFER",
    severity: FindingSeverity.High,
    type: FindingType.Suspicious,
    metadata: {
      suspiciousContract: suspiciousContract.address,
      suspiciousContractCreator: suspiciousContract.creator,
      msgSender,
      owner,
      receiver,
      anomalyScore: anomalyScore.toFixed(2),
    },
    addresses: [asset],
    labels: [
      Label.fromObject({
        entity: suspiciousContract.address,
        entityType: EntityType.Address,
        label: "Ice Phishing Attacker",
        confidence: 0.6,
      }),
      Label.fromObject({
        entity: suspiciousContract.creator,
        entityType: EntityType.Address,
        label: "Ice Phishing Attacker",
        confidence: 0.6,
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

function createTransferScamCreatorAlert(
  msgSender,
  owner,
  receiver,
  asset,
  scamAddress,
  scamDomains,
  anomalyScore,
  txHash
) {
  return Finding.fromObject({
    name: "Contract, created by a known scam address, was involved in an asset transfer",
    description: `${msgSender} transferred assets from ${owner} to ${receiver}`,
    alertId: "ICE-PHISHING-SCAM-CREATOR-TRANSFER",
    severity: FindingSeverity.Critical,
    type: FindingType.Exploit,
    metadata: {
      scamAddress,
      scamDomains,
      msgSender,
      owner,
      receiver,
      anomalyScore: anomalyScore.toFixed(2),
    },
    addresses: [asset],
    labels: [
      Label.fromObject({
        entity: scamAddress,
        entityType: EntityType.Address,
        label: "Ice Phishing Attacker",
        confidence: 0.95,
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
      anomalyScore: anomalyScore.toFixed(2),
    },
    addresses: assets,
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Ice Phishing Attacker",
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
      anomalyScore: anomalyScore.toFixed(2),
    },
    addresses: assets,
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Ice Phishing Attacker",
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
      anomalyScore: anomalyScore.toFixed(2),
    },
    addresses: asset,
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Ice Phishing Attacker",
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
      anomalyScore: anomalyScore.toFixed(2),
    },
    addresses: asset,
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Ice Phishing Attacker",
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

function getEtherscanContractUrl(address, chainId) {
  const { urlContract, key } = etherscanApis[chainId];
  return `${urlContract}&address=${address}&apikey=${key}`;
}

function getEtherscanAddressUrl(address, chainId) {
  const { urlAccount, key } = etherscanApis[chainId];
  return `${urlAccount}&address=${address}&startblock=0&endblock=99999999&sort=asc&apikey=${key}`;
}

async function getContractCreator(address, chainId) {
  const { urlContractCreation, key } = etherscanApis[chainId];
  const url = `${urlContractCreation}&contractaddresses=${address}&apikey=${key}`;

  const result = await axios.get(url);

  if (result.data.message.startsWith("NOTOK")) {
    console.log(`block explorer error occured; skipping check for ${address}`);
    return null;
  }

  return result.data.result[0].contractCreator;
}

async function getEoaType(address, provider, blockNumber) {
  const nonce = await provider.getTransactionCount(address, blockNumber);
  return nonce > nonceThreshold ? AddressType.EoaWithHighNonce : AddressType.EoaWithLowNonce;
}

async function getContractType(address, chainId) {
  let result;

  result = await axios.get(getEtherscanContractUrl(address, chainId));

  if (result.data.message.startsWith("NOTOK") && result.data.result !== "Contract source code not verified") {
    console.log(`block explorer error occured; skipping check for ${address}`);
    return null;
  }

  const isVerified = result.data.status === "1";

  result = await axios.get(getEtherscanAddressUrl(address, chainId));
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
    // the address is ignored
    if (
      isOwner ||
      type === AddressType.EoaWithHighNonce ||
      type === AddressType.HighNumTxsVerifiedContract ||
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
  const code = await provider.getCode(address);
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

async function getSuspiciousContracts(chainId, blockNumber, init) {
  let contracts = [];
  let startingCursor;
  if (!init) {
    const fortaResponse = await getAlerts({
      botIds: [MALICIOUS_SMART_CONTRACT_ML_BOT_V2_ID],
      chainId: chainId,
      blockNumberRange: {
        startBlockNumber: blockNumber - 20000,
        endBlockNumber: blockNumber,
      },
      first: 6000,
    });

    fortaResponse.alerts.forEach((alert) => {
      contracts.push({ address: alert.description.slice(-42), creator: alert.description.slice(0, 42) });
    });

    startingCursor = fortaResponse.pageInfo.endCursor;
    while (startingCursor.blockNumber > 0) {
      const fortaResponse = await getAlerts({
        botIds: [MALICIOUS_SMART_CONTRACT_ML_BOT_V2_ID],
        chainId: chainId,
        blockNumberRange: {
          startBlockNumber: blockNumber - 20000,
          endBlockNumber: blockNumber,
        },
        first: 1000,
        startingCursor: startingCursor,
      });

      fortaResponse.alerts.forEach((alert) => {
        contracts.push({ address: alert.description.slice(-42), creator: alert.description.slice(0, 42) });
      });

      startingCursor = fortaResponse.pageInfo.endCursor;
    }
    contracts = contracts.map((contract) => {
      return {
        address: ethers.utils.getAddress(contract.address),
        creator: ethers.utils.getAddress(contract.creator),
      };
    });
    return new Set(contracts);
  } else {
    const fortaResponse = await getAlerts({
      botIds: [MALICIOUS_SMART_CONTRACT_ML_BOT_V2_ID],
      chainId: chainId,
      blockNumberRange: {
        startBlockNumber: blockNumber - 1,
        endBlockNumber: blockNumber,
      },
      first: 1000,
    });

    fortaResponse.alerts.forEach((alert) => {
      contracts.push({ address: alert.description.slice(-42), creator: alert.description.slice(0, 42) });
    });
    contracts = contracts.map((contract) => {
      return {
        address: ethers.utils.getAddress(contract.address),
        creator: ethers.utils.getAddress(contract.creator),
      };
    });
    return new Set(contracts);
  }
}

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
  createPermitSuspiciousContractAlert,
  createApprovalScamAlert,
  createApprovalScamCreatorAlert,
  createApprovalSuspiciousContractAlert,
  createTransferScamAlert,
  createTransferScamCreatorAlert,
  createTransferSuspiciousContractAlert,
  getAddressType,
  getContractCreator,
  getSuspiciousContracts,
  getBalance,
  getERC1155Balance,
};

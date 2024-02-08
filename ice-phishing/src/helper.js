const { Finding, FindingSeverity, FindingType, ethers, getAlerts, Label, EntityType } = require("forta-agent");
const { default: axios } = require("axios");
const LRU = require("lru-cache");
const util = require("util");
const { nonceThreshold, contractTxsThreshold, verifiedContractTxsThreshold } = require("../bot-config.json");
const { etherscanApis } = require("./config");
const { keys } = require("./keys");
const {
  MALICIOUS_SMART_CONTRACT_ML_BOT_V2_ID,
  ERC_20_721_INTERFACE,
  ERC_1155_INTERFACE,
  STABLECOINS,
} = require("./utils");
const errorCache = require("./errorCache");
const AddressType = require("./address-type");

// Computes the data needed for an alert
function getEventInformation(eventsArray) {
  const { length } = eventsArray;
  const firstTxHash = eventsArray[0].hash;
  const lastTxHash = eventsArray[length - 1].hash;

  // Remove duplicates
  const assets = [...new Set(eventsArray.map((e) => e.asset))];
  const accounts = [...new Set(eventsArray.map((e) => e.owner))];

  // Transfers
  const assetIdTuples = [
    ...new Set(
      eventsArray.map((e) => {
        const id = e.id
          ? Array.isArray(e.id)
            ? e.id.map((item) => ethers.BigNumber.from(item).toString())
            : [ethers.BigNumber.from(e.id).toString()]
          : [];
        return JSON.stringify([id, e.asset]);
      })
    ),
  ].map(JSON.parse);

  const days = Math.ceil((eventsArray[length - 1].timestamp - eventsArray[0].timestamp) / 86400);

  return {
    firstTxHash,
    lastTxHash,
    assets,
    assetIdTuples,
    accounts,
    days,
  };
}

function createErrorAlert(errorDescription, errorSource, errorStacktrace) {
  return Finding.fromObject({
    name: "Ice Phishing Bot Error",
    description: errorDescription,
    alertId: "ICE-PHISHING-BOT-ERROR",
    severity: FindingSeverity.Info,
    type: FindingType.Info,
    metadata: {
      errorSource,
      errorStacktrace,
    },
  });
}

function createHighNumApprovalsAlertERC20(spender, approvalsArray, anomalyScore) {
  const { firstTxHash, lastTxHash, assets, accounts, days } = getEventInformation(approvalsArray);
  const alertId = "ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS";
  const now = new Date();
  const currentDate = now.getDate();
  const currentMonth = now.getMonth() + 1;
  const currentYear = now.getFullYear();

  const uniqueKey = ethers.utils.keccak256(
    ethers.utils.toUtf8Bytes(spender + alertId + currentDate + currentMonth + currentYear)
  );
  return Finding.fromObject({
    name: "High number of accounts granted approvals for ERC-20 tokens",
    description: `${spender} obtained transfer approval for ${assets.length} ERC-20 tokens by ${accounts.length} accounts over period of ${days} days.`,
    alertId,
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
    uniqueKey,
  });
}

function createHighNumApprovalsInfoAlertERC20(spender, approvalsArray, anomalyScore) {
  const { firstTxHash, lastTxHash, assets, accounts, days } = getEventInformation(approvalsArray);
  const alertId = "ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS-INFO";
  const now = new Date();
  const currentDate = now.getDate();
  const currentMonth = now.getMonth() + 1;
  const currentYear = now.getFullYear();

  const uniqueKey = ethers.utils.keccak256(
    ethers.utils.toUtf8Bytes(spender + alertId + currentDate + currentMonth + currentYear)
  );
  return Finding.fromObject({
    name: "High number of accounts granted approvals for ERC-20 tokens",
    description: `${spender} obtained transfer approval for ${assets.length} ERC-20 tokens by ${accounts.length} accounts over period of ${days} days.`,
    alertId,
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
    uniqueKey,
  });
}

function createHighNumApprovalsAlertERC721(spender, approvalsArray, anomalyScore) {
  const { firstTxHash, lastTxHash, assets, accounts, days } = getEventInformation(approvalsArray);
  const alertId = "ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS";
  const now = new Date();
  const currentDate = now.getDate();
  const currentMonth = now.getMonth() + 1;
  const currentYear = now.getFullYear();

  const uniqueKey = ethers.utils.keccak256(
    ethers.utils.toUtf8Bytes(spender + alertId + currentDate + currentMonth + currentYear)
  );
  return Finding.fromObject({
    name: "High number of accounts granted approvals for ERC-721 tokens",
    description: `${spender} obtained transfer approval for ${assets.length} ERC-721 tokens by ${accounts.length} accounts over period of ${days} days.`,
    alertId,
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
    uniqueKey,
  });
}

function createHighNumApprovalsInfoAlertERC721(spender, approvalsArray, anomalyScore) {
  const { firstTxHash, lastTxHash, assets, accounts, days } = getEventInformation(approvalsArray);
  const alertId = "ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS-INFO";
  const now = new Date();
  const currentDate = now.getDate();
  const currentMonth = now.getMonth() + 1;
  const currentYear = now.getFullYear();

  const uniqueKey = ethers.utils.keccak256(
    ethers.utils.toUtf8Bytes(spender + alertId + currentDate + currentMonth + currentYear)
  );
  return Finding.fromObject({
    name: "High number of accounts granted approvals for ERC-721 tokens",
    description: `${spender} obtained transfer approval for ${assets.length} ERC-721 tokens by ${accounts.length} accounts over period of ${days} days.`,
    alertId,
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
    uniqueKey,
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
    name: "Scam address, flagged in the Scam Sniffer DB, was involved in an ERC-20 permission",
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
    name: "Contract created by a scam address (flagged in the Scam Sniffer DB) was involved in an ERC-20 permission",
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
      anomalyScore: anomalyScore.toString(),
    },
    addresses: [asset],
    labels: [
      Label.fromObject({
        entity: spender,
        entityType: EntityType.Address,
        label: "Attacker",
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
    name: "Scam address, flagged in the Scam Sniffer DB, got approval to spend assets",
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
      anomalyScore: anomalyScore.toString(),
    },
    addresses: [asset],
    labels: [
      Label.fromObject({
        entity: suspiciousSpender,
        entityType: EntityType.Address,
        label: "Attacker",
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
    name: "Contract, created by a known scam address (flagged in the Scam Sniffer DB), got approval to spend assets",
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

function createTransferScamAlert(
  msgSender,
  owner,
  receiver,
  asset,
  id,
  scamAddresses,
  scamDomains,
  anomalyScore,
  txHash
) {
  let labels = [];
  if (id) {
    if (Array.isArray(id)) {
      id.map((item) => {
        labels.push(
          Label.fromObject({
            entity: item.toString() + "," + asset,
            entityType: EntityType.Address,
            label: "NFT",
            confidence: 1,
          })
        );
      });
    } else {
      labels.push(
        Label.fromObject({
          entity: id.toString() + "," + asset,
          entityType: EntityType.Address,
          label: "NFT",
          confidence: 1,
        })
      );
    }
  }
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
    name: "Scam address, flagged in the Scam Sniffer DB, was involved in an asset transfer",
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
    labels,
  });
}

function createTransferSuspiciousContractAlert(
  msgSender,
  owner,
  receiver,
  asset,
  id,
  suspiciousContract,
  anomalyScore,
  txHash
) {
  let labels = [
    Label.fromObject({
      entity: suspiciousContract.address,
      entityType: EntityType.Address,
      label: "Attacker",
      confidence: 0.6,
    }),
    Label.fromObject({
      entity: suspiciousContract.creator,
      entityType: EntityType.Address,
      label: "Attacker",
      confidence: 0.6,
    }),
    Label.fromObject({
      entity: txHash,
      entityType: EntityType.Transaction,
      label: "Transfer",
      confidence: 1,
    }),
  ];

  if (id) {
    if (Array.isArray(id)) {
      id.map((item) => {
        labels.push(
          Label.fromObject({
            entity: item.toString() + "," + asset,
            entityType: EntityType.Address,
            label: "NFT",
            confidence: 1,
          })
        );
      });
    } else {
      labels.push(
        Label.fromObject({
          entity: id.toString() + "," + asset,
          entityType: EntityType.Address,
          label: "NFT",
          confidence: 1,
        })
      );
    }
  }

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
      anomalyScore: anomalyScore.toString(),
    },
    addresses: [asset],
    labels,
  });
}

function createHighNumTransfersAlert(spender, transfersArray, anomalyScore) {
  const { firstTxHash, lastTxHash, assets, assetIdTuples, accounts, days } = getEventInformation(transfersArray);
  const alertId = "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS";
  const now = new Date();
  const currentDate = now.getDate();
  const currentMonth = now.getMonth() + 1;
  const currentYear = now.getFullYear();

  const uniqueKey = ethers.utils.keccak256(
    ethers.utils.toUtf8Bytes(spender + alertId + currentDate + currentMonth + currentYear)
  );
  let labels = [
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
  ];

  assetIdTuples.map((tuple) => {
    if (tuple[0]) {
      if (Array.isArray(tuple[0])) {
        tuple[0].map((item) => {
          labels.push(
            Label.fromObject({
              entity: item + "," + tuple[1],
              entityType: EntityType.Address,
              label: "NFT",
              confidence: 1,
            })
          );
        });
      } else {
        labels.push(
          Label.fromObject({
            entity: tuple[0] + "," + tuple[1],
            entityType: EntityType.Address,
            label: "NFT",
            confidence: 1,
          })
        );
      }
    }
  });
  return Finding.fromObject({
    name: "Previously approved assets transferred",
    description: `${spender} transferred ${assets.length} assets from ${accounts.length} accounts over period of ${days} days.`,
    alertId,
    severity: FindingSeverity.High,
    type: FindingType.Exploit,
    metadata: {
      firstTxHash,
      lastTxHash,
      anomalyScore: anomalyScore.toString(),
    },
    addresses: assets,
    labels,
    uniqueKey,
  });
}

function createHighNumTransfersLowSeverityAlert(spender, transfersArray, anomalyScore) {
  const { firstTxHash, lastTxHash, assets, assetIdTuples, accounts, days } = getEventInformation(transfersArray);
  const alertId = "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS-LOW";
  const now = new Date();
  const currentDate = now.getDate();
  const currentMonth = now.getMonth() + 1;
  const currentYear = now.getFullYear();

  const uniqueKey = ethers.utils.keccak256(
    ethers.utils.toUtf8Bytes(spender + alertId + currentDate + currentMonth + currentYear)
  );

  let labels = [
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
  ];
  assetIdTuples.map((tuple) => {
    if (tuple[0]) {
      if (Array.isArray(tuple[0])) {
        tuple[0].map((item) => {
          labels.push(
            Label.fromObject({
              entity: item + "," + tuple[1],
              entityType: EntityType.Address,
              label: "NFT",
              confidence: 1,
            })
          );
        });
      } else {
        labels.push(
          Label.fromObject({
            entity: tuple[0] + "," + tuple[1],
            entityType: EntityType.Address,
            label: "NFT",
            confidence: 1,
          })
        );
      }
    }
  });
  return Finding.fromObject({
    name: "Previously approved assets transferred",
    description: `${spender} transferred ${assets.length} assets from ${accounts.length} accounts over period of ${days} days.`,
    alertId,
    severity: FindingSeverity.Low,
    type: FindingType.Suspicious,
    metadata: {
      firstTxHash,
      lastTxHash,
      anomalyScore: anomalyScore.toString(),
    },
    addresses: assets,
    labels,
    uniqueKey,
  });
}

function createPigButcheringAlert(receiver, transfersArray, txHash, anomalyScore) {
  const alertId = "ICE-PHISHING-PIG-BUTCHERING";
  const now = new Date();
  const currentDate = now.getDate();
  const currentMonth = now.getMonth() + 1;
  const currentYear = now.getFullYear();

  const uniqueKey = ethers.utils.keccak256(
    ethers.utils.toUtf8Bytes(receiver + txHash + alertId + currentDate + currentMonth + currentYear)
  );

  let labels = [];
  let metadata = {};
  metadata["receiver"] = receiver;
  metadata["anomalyScore"] = anomalyScore.toString();

  const uniqueInitiators = new Set();

  labels.push(
    Label.fromObject({
      entity: txHash,
      entityType: EntityType.Transaction,
      label: "Attack",
      confidence: 0.7,
    })
  );

  labels.push(
    Label.fromObject({
      entity: receiver,
      entityType: EntityType.Address,
      label: "Attacker",
      confidence: 0.7,
    })
  );

  let initiatorIndex = 1;
  for (let index = 1; index <= transfersArray.length; index++) {
    const { initiator, owner } = transfersArray[index - 1];

    // Add initiator to the uniqueInitiators set if it's not already present
    if (!uniqueInitiators.has(initiator)) {
      uniqueInitiators.add(initiator);
      metadata[`initiator${initiatorIndex}`] = initiator;
      initiatorIndex++;

      labels.push(
        Label.fromObject({
          entity: initiator,
          entityType: EntityType.Address,
          label: "Attacker",
          confidence: 0.7,
        })
      );
    }

    metadata[`victim${index}`] = owner;

    // Add labels for owners as "Victim" with confidence 0.7
    labels.push(
      Label.fromObject({
        entity: owner,
        entityType: EntityType.Address,
        label: "Victim",
        confidence: 0.7,
      })
    );
  }

  return Finding.fromObject({
    name: "Possible Pig Butchering Attack",
    description: `${receiver} received funds through a pig butchering attack`,
    alertId,
    severity: FindingSeverity.Critical,
    type: FindingType.Suspicious,
    metadata,
    labels,
    uniqueKey,
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

function createZeroNonceAllowanceAlert(victim, attacker, asset, anomalyScore, txHash) {
  return Finding.fromObject({
    name: "Approval/Permission has been given to a 0 nonce address",
    description: `${attacker} received allowance from ${victim} to spend (${asset}) tokens`,
    alertId: "ICE-PHISHING-ZERO-NONCE-ALLOWANCE",
    severity: FindingSeverity.High,
    type: FindingType.Suspicious,
    metadata: {
      attacker,
      victim,
      anomalyScore: anomalyScore.toString(),
    },
    addresses: [asset],
    labels: [
      Label.fromObject({
        entity: attacker,
        entityType: EntityType.Address,
        label: "Attacker",
        confidence: 0.7,
      }),
      Label.fromObject({
        entity: victim,
        entityType: EntityType.Address,
        label: "Victim",
        confidence: 0.7,
      }),
      Label.fromObject({
        entity: txHash,
        entityType: EntityType.Transaction,
        label: "Attack",
        confidence: 0.7,
      }),
    ],
  });
}

function createZeroNonceAllowanceTransferAlert(victim, attackers, asset, anomalyScore, txHash) {
  let labels = [];

  const metadata = {
    anomalyScore: anomalyScore.toString(),
  };
  metadata["victim"] = victim;

  attackers.forEach((attacker, index) => {
    const attackerName = `attacker${index + 1}`;
    metadata[attackerName] = attacker;

    const attackerLabel = Label.fromObject({
      entity: attacker,
      entityType: EntityType.Address,
      label: "Attacker",
      confidence: 0.9,
      remove: false,
    });
    labels.push(attackerLabel);
  });

  return Finding.fromObject({
    name: "Approval/Permission has been given to a 0 nonce address during a transfer",
    description: `${attackers[0]} received allowance from ${victim} and spent (${asset}) tokens`,
    alertId: "ICE-PHISHING-ZERO-NONCE-ALLOWANCE-TRANSFER",
    severity: FindingSeverity.Critical,
    type: FindingType.Suspicious,
    metadata,
    addresses: [asset],
    labels: [
      ...labels,
      Label.fromObject({
        entity: victim,
        entityType: EntityType.Address,
        label: "Victim",
        confidence: 0.9,
      }),
      Label.fromObject({
        entity: txHash,
        entityType: EntityType.Transaction,
        label: "Attack",
        confidence: 0.9,
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

function getEtherscanAddressUrl(address, chainId, offset, order) {
  const { urlAccount } = etherscanApis[Number(chainId)];
  const key = getBlockExplorerKey(Number(chainId));
  return `${urlAccount}&address=${address}&startblock=0&endblock=999999999&page=1&offset=${
    offset + 1
  }&sort=${order}&apikey=${key}`;
}

function getEtherscanTokenTxUrl(address, token, chainId) {
  const { urlAccountToken } = etherscanApis[Number(chainId)];
  const key = getBlockExplorerKey(Number(chainId));
  return `${urlAccountToken}&contractaddress=${token}&address=${address}&startblock=0&endblock=99999999&page=1&offset=1&sort=asc&apikey=${key}`;
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

async function getContractCreationHash(address, chainId) {
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
  const contractCreationHash = result.data.result[0].txHash;

  // E.g. contract 0x85149247691df622eaf1a8bd0cafd40bc45154a9 on Optimism returns "GENESIS" as the creator/hash
  if (!contractCreationHash.startsWith("0x")) {
    console.log("Contract creation is not a valid hash:", contractCreationHash);
    return null;
  } else {
    return contractCreationHash;
  }
}

async function hasTransferredNonStablecoins(address, chainId) {
  const url = getEtherscanAddressUrl(address, chainId, 100, "desc");
  let result;

  let retries = 2;
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
  const hasTransferredNonStablecoins = result.data.result.some(
    (tx) => tx.functionName.startsWith("transferFrom") && !STABLECOINS.includes(tx.to)
  );

  return hasTransferredNonStablecoins;
}

async function getInitialERC20Funder(address, token, chainId) {
  const url = getEtherscanTokenTxUrl(address, token, chainId);
  let result;
  let initialFunder = "";

  let retries = 2;
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

  initialFunder = result.data.result[0].from;
  return initialFunder;
}

async function getLabel(address) {
  const maxRetries = 3;

  const url = `https://api.forta.network/labels/state?entities=${address}&sourceIds=etherscan-tags&limit=1`;

  for (let i = 0; i < maxRetries; i++) {
    try {
      const response = await (await fetch(url)).json();
      return response.events.length > 0 ? response.events[0]["label"]["label"] : "";
    } catch (error) {
      console.log(`Error fetching label: ${error}`);

      // wait for 1 second before retrying
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }

  return "";
}

const cachedNonces = new LRU({ max: 5 });

async function getTransactionCount(address, provider, blockNumber) {
  let nonce = 100000;
  let tries = 0;
  const maxTries = 3;
  const cacheKey = `${address}-${blockNumber}`;

  if (cachedNonces.has(cacheKey)) {
    return cachedNonces.get(cacheKey);
  }

  while (tries < maxTries) {
    try {
      nonce = await provider.getTransactionCount(address, blockNumber);
      cachedNonces.set(cacheKey, nonce);
      break; // exit the loop if successful
    } catch (e) {
      tries++;
      if (tries === maxTries) {
        const stackTrace = util.inspect(e, { showHidden: false, depth: null });
        errorCache.add(createErrorAlert(e.toString(), "helper.getEoaType", stackTrace));
      }
      await new Promise((resolve) => setTimeout(resolve, 1000)); // wait for 1 second before retrying
    }
  }
  return nonce;
}

async function getEoaType(address, provider, blockNumber) {
  const nonce = await getTransactionCount(address, provider, blockNumber);
  return nonce > nonceThreshold ? AddressType.EoaWithHighNonce : AddressType.EoaWithLowNonce;
}

async function getContractType(address, chainId) {
  let result;

  let retries = 2;
  for (let i = 0; i <= retries; i++) {
    try {
      result = await axios.get(getEtherscanContractUrl(address, chainId));
      break; // Exit the loop if successful
    } catch {
      if (i === retries) {
        throw new Error(
          `All retry attempts to call block explorer (URL: ${getEtherscanContractUrl(address, chainId)}) failed`
        );
      } else {
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
    ? getEtherscanAddressUrl(address, chainId, verifiedContractTxsThreshold, "asc")
    : getEtherscanAddressUrl(address, chainId, contractTxsThreshold, "asc");
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
    } catch (e) {
      tries++;
      if (tries === maxTries) {
        const stackTrace = util.inspect(e, { showHidden: false, depth: null });
        errorCache.add(createErrorAlert(e.toString(), "helper.getEoaType", stackTrace));
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

async function haveInteractedMoreThanOnce(spender, assetOwnerArray, chainId) {
  const maxRetries = 3;
  let result;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      result = await axios.get(getEtherscanAddressUrl(spender, chainId, 9000, "desc"));
      if (result.data.message.startsWith("NOTOK") || result.data.message.startsWith("Query Timeout")) {
        console.log(`block explorer error occured (attempt ${attempt}); retrying check for ${spender}`);
        if (attempt === maxRetries) {
          console.log(`block explorer error occured (final attempt); skipping check for ${spender}`);
          return true;
        }
      } else {
        break;
      }
    } catch (err) {
      console.log(err);
      console.log(`An error occurred during the fetch (attempt ${attempt}):`);
      if (attempt === maxRetries) {
        console.log(`Error during fetch (final attempt); skipping check for ${spender}`);
        return true;
      }
    }
  }

  for (const [asset, owner] of assetOwnerArray) {
    let numberOfInteractions = 0;
    for (const tx of result.data.result) {
      if (
        tx.from === spender.toLowerCase() &&
        tx.to === asset &&
        tx.input.includes(owner.toLowerCase().replace(/^0x/, ""))
      ) {
        numberOfInteractions++;
        if (numberOfInteractions > 1) {
          console.log(`Found ${numberOfInteractions} interactions between ${spender} and ${asset}`);
          return true;
        }
      }
    }
  }

  return false;
}

async function hasZeroTransactions(spender, chainId) {
  const maxRetries = 3;
  let result;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      result = await axios.get(getEtherscanAddressUrl(spender, chainId, 10, "desc"));
      if (result.data.message.startsWith("NOTOK") || result.data.message.startsWith("Query Timeout")) {
        console.log(`block explorer error occured (attempt ${attempt}); retrying check for ${spender}`);
        if (attempt === maxRetries) {
          console.log(`block explorer error occured (final attempt); skipping check for ${spender}`);
          return false;
        }
      } else {
        break;
      }
    } catch (err) {
      console.log(err);
      console.log(`An error occurred during the fetch (attempt ${attempt}):`);
      if (attempt === maxRetries) {
        console.log(`Error during fetch (final attempt); skipping check for ${spender}`);
        return false;
      }
    }
  }
  if (result.data.message === "No transactions found") return true;
}

async function getNumberOfUniqueTxInitiators(contract, chainId) {
  const maxRetries = 3;
  let result;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      result = await axios.get(getEtherscanAddressUrl(contract, chainId, 9999));
      if (result.data.message.startsWith("NOTOK") || result.data.message.startsWith("Query Timeout")) {
        console.log(`block explorer error occured (attempt ${attempt}); retrying check for ${contract}`);
        if (attempt === maxRetries) {
          console.log(`block explorer error occured (final attempt); skipping check for ${contract}`);
          return false;
        }
      } else {
        break;
      }
    } catch (err) {
      console.log(err);
      console.log(`An error occurred during the fetch (attempt ${attempt}):`);
      if (attempt === maxRetries) {
        console.log(`Error during fetch (final attempt); skipping check for ${contract}`);
        return false;
      }
    }
  }
  let uniqueTxInitiators = new Set(result.data.result.map((tx) => tx.from));
  return uniqueTxInitiators.size;
}

async function getSuspiciousContracts(chainId, blockNumber, init) {
  let contracts = [];
  let startingCursor;

  if (!init) {
    const fortaResponse = await getAlerts({
      botIds: [MALICIOUS_SMART_CONTRACT_ML_BOT_V2_ID],
      alertId: "SUSPICIOUS-CONTRACT-CREATION",
      chainId: chainId,
      blockNumberRange: {
        startBlockNumber: blockNumber - 20000,
        endBlockNumber: blockNumber,
      },
      first: 5000,
    });

    fortaResponse.alerts.forEach((alert) => {
      contracts.push({ address: alert.description.slice(-42), creator: alert.description.slice(0, 42) });
    });

    startingCursor = fortaResponse.pageInfo.endCursor;
    while (startingCursor.blockNumber > 0) {
      const fortaResponse = await getAlerts({
        botIds: [MALICIOUS_SMART_CONTRACT_ML_BOT_V2_ID],
        alertId: "SUSPICIOUS-CONTRACT-CREATION",
        chainId: chainId,
        blockNumberRange: {
          startBlockNumber: blockNumber - 15000,
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
      alertId: "SUSPICIOUS-CONTRACT-CREATION",
      chainId: chainId,
      blockNumberRange: {
        startBlockNumber: blockNumber - 240,
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

const populateScamSnifferMap = (scamSnifferDB) => {
  const scamSnifferMap = new Map();

  Object.keys(scamSnifferDB).map((key) => {
    const addresses = scamSnifferDB[key];

    for (const address of addresses) {
      if (scamSnifferMap.has(address)) {
        const domains = scamSnifferMap.get(address);
        domains.push(key);
      } else {
        scamSnifferMap.set(address, [key]);
      }
    }
  });

  return scamSnifferMap;
};

const fetchScamDomains = (scamSnifferMap, addresses) => {
  let scamDomains = [];

  addresses.forEach((address) => {
    address = address.toLowerCase();
    if (scamSnifferMap.has(address)) {
      scamDomains = [...scamDomains, ...scamSnifferMap.get(address)];
    }
  });

  return [...new Set(scamDomains)];
};

// Logic to filter out failSafe vaults

const failSafeCreationCode =
  "0x60806040526040516106cc3803806106cc83398101604081905261002291610420565b61002e82826000610035565b505061054a565b61003e836100f6565b6040516001600160a01b038416907f1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e90600090a260008251118061007f5750805b156100f1576100ef836001600160a01b0316635c60da1b6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156100c5573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906100e991906104e0565b8361027a565b505b505050565b6001600160a01b0381163b6101605760405162461bcd60e51b815260206004820152602560248201527f455243313936373a206e657720626561636f6e206973206e6f74206120636f6e6044820152641d1c9858dd60da1b60648201526084015b60405180910390fd5b6101d4816001600160a01b0316635c60da1b6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156101a1573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906101c591906104e0565b6001600160a01b03163b151590565b6102395760405162461bcd60e51b815260206004820152603060248201527f455243313936373a20626561636f6e20696d706c656d656e746174696f6e206960448201526f1cc81b9bdd08184818dbdb9d1c9858dd60821b6064820152608401610157565b7fa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d5080546001600160a01b0319166001600160a01b0392909216919091179055565b606061029f83836040518060600160405280602781526020016106a5602791396102a6565b9392505050565b6060600080856001600160a01b0316856040516102c391906104fb565b600060405180830381855af49150503d80600081146102fe576040519150601f19603f3d011682016040523d82523d6000602084013e610303565b606091505b5090925090506103158683838761031f565b9695505050505050565b6060831561038e578251600003610387576001600160a01b0385163b6103875760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e74726163740000006044820152606401610157565b5081610398565b61039883836103a0565b949350505050565b8151156103b05781518083602001fd5b8060405162461bcd60e51b81526004016101579190610517565b80516001600160a01b03811681146103e157600080fd5b919050565b634e487b7160e01b600052604160045260246000fd5b60005b838110156104175781810151838201526020016103ff565b50506000910152565b6000806040838503121561043357600080fd5b61043c836103ca565b60208401519092506001600160401b038082111561045957600080fd5b818501915085601f83011261046d57600080fd5b81518181111561047f5761047f6103e6565b604051601f8201601f19908116603f011681019083821181831017156104a7576104a76103e6565b816040528281528860208487010111156104c057600080fd5b6104d18360208301602088016103fc565b80955050505050509250929050565b6000602082840312156104f257600080fd5b61029f826103ca565b6000825161050d8184602087016103fc565b9190910192915050565b60208152600082518060208401526105368160408501602087016103fc565b601f01601f19169190910160400192915050565b61014c806105596000396000f3fe60806040523661001357610011610017565b005b6100115b610027610022610029565b6100c2565b565b600061005c7fa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50546001600160a01b031690565b6001600160a01b0316635c60da1b6040518163ffffffff1660e01b8152600401602060405180830381865afa158015610099573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906100bd91906100e6565b905090565b3660008037600080366000845af43d6000803e8080156100e1573d6000f35b3d6000fd5b6000602082840312156100f857600080fd5b81516001600160a01b038116811461010f57600080fd5b939250505056fea26469706673582212204afd408915d0bea91a3121bf3a37a1f9496847b5c848fb2c7f8e78bf9cb1a8a664736f6c63430008140033416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564";

const failSafeInitializeSelector = "0x485cc955";
const failSafeBeaconProxy = {
  1: ["0x9bba00532d2359c00bdb33e4a8116d0f03b6d30a", "0x2fb612a52af434089fc7550af6e72cfe638a00e3"],
  56: ["0x47eeb3ef6d62bc6d0b08b60271681fe658b10c3e", "0x90f5d1e711444366c3ce192b7222e8830c4a2f7e"],
  137: ["0xeb9e5ff948603c663cd8699f093cd5a1cd2d34be", "0x1da83e889c271ed37af1d590e47fd46f953071a6"],
};

const failSafeBeacon = {
  1: ["0x8aa6afdaccdbf546f8e8b373b0b8ebb79d252801", "0x451ca9dc32db95c07380320ac2b055d143ef1f52"],
  56: ["0xa34b9e8929740ec149414294cbbdac6c76d67920", "0x1c75de11275aee74ab4d85a61f85867b3746fd16"],
  137: ["0x35a35bb76d1619c14fb99386cb6f9c1ffc86ad4f", "0x3fe0f063903eb4360088ce1a97ab111142ecc87a"],
};

const getBytecode = (beaconProxy, protectedAddr) => {
  const encodedParams = ethers.utils.defaultAbiCoder.encode(["address", "address"], [beaconProxy, protectedAddr]);
  return failSafeCreationCode + encodedParams.slice(2); // Remove '0x' from the encodedParams
};

const getBytecode1 = (beacon, stream) => {
  const encodedParams = ethers.utils.defaultAbiCoder.encode(["address", "bytes"], [beacon, stream]);
  return failSafeCreationCode + encodedParams.slice(2); // Remove '0x' from the encodedParams
};
const isFailSafe = (spender, protectedAddr, chainId) => {
  if (![1, 56, 137].includes(chainId)) return false;

  const proxies = failSafeBeaconProxy[chainId];
  const beacons = failSafeBeacon[chainId];

  for (let i = 0; i < proxies.length; i++) {
    const proxy = proxies[i];
    const beacon = beacons[i]; // Assuming the same index for beacons

    const packedParams = ethers.utils.solidityPack(
      ["bytes1", "address", "uint256", "bytes32"],
      [
        "0xff",
        protectedAddr,
        1, // version
        ethers.utils.solidityKeccak256(["bytes"], [getBytecode(proxy, protectedAddr)]),
      ]
    );
    const salt = ethers.utils.solidityKeccak256(["bytes"], [packedParams]);

    const encodedParams = ethers.utils.defaultAbiCoder.encode(["address", "address"], [proxy, protectedAddr]);
    const stream = failSafeInitializeSelector + encodedParams.slice(2);

    const packedParams2 = ethers.utils.solidityPack(
      ["bytes1", "address", "bytes32", "bytes32"],
      ["0xff", proxy, salt, ethers.utils.solidityKeccak256(["bytes"], [getBytecode1(beacon, stream)])]
    );
    const hash = ethers.utils.solidityKeccak256(["bytes"], [packedParams2]);

    const address = ethers.utils.getAddress(ethers.utils.hexDataSlice(hash, 12)); // Slice the last 20 bytes and get the address

    if (spender.toLowerCase() === address.toLowerCase()) {
      return true; // Return true if at least one pair matches
    }
  }

  return false; // Return false if none of the pairs match
};

module.exports = {
  createErrorAlert,
  createHighNumApprovalsAlertERC20,
  createHighNumApprovalsInfoAlertERC20,
  createHighNumApprovalsAlertERC721,
  createHighNumApprovalsInfoAlertERC721,
  createHighNumTransfersAlert,
  createHighNumTransfersLowSeverityAlert,
  createPigButcheringAlert,
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
  createTransferSuspiciousContractAlert,
  createSweepTokenAlert,
  createOpenseaAlert,
  createZeroNonceAllowanceAlert,
  createZeroNonceAllowanceTransferAlert,
  getAddressType,
  getEoaType,
  getContractCreator,
  hasTransferredNonStablecoins,
  getInitialERC20Funder,
  getLabel,
  getSuspiciousContracts,
  haveInteractedMoreThanOnce,
  getBalance,
  getERC1155Balance,
  isOpenseaProxy,
  checkObjectSizeAndCleanup,
  populateScamSnifferMap,
  fetchScamDomains,
  getTransactionCount,
  getContractCreationHash,
  hasZeroTransactions,
  getNumberOfUniqueTxInitiators,
  isFailSafe,
};

const { Finding, FindingSeverity, FindingType, Label, EntityType } = require("forta-agent");
const { ethers } = require("forta-bot");

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

  const uniqueKey = ethers.keccak256(ethers.toUtf8Bytes(spender + alertId + currentDate + currentMonth + currentYear));
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

  const uniqueKey = ethers.keccak256(ethers.toUtf8Bytes(spender + alertId + currentDate + currentMonth + currentYear));
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

  const uniqueKey = ethers.keccak256(ethers.toUtf8Bytes(spender + alertId + currentDate + currentMonth + currentYear));
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

  const uniqueKey = ethers.keccak256(ethers.toUtf8Bytes(spender + alertId + currentDate + currentMonth + currentYear));
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

  const uniqueKey = ethers.keccak256(ethers.toUtf8Bytes(spender + alertId + currentDate + currentMonth + currentYear));
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

  const uniqueKey = ethers.keccak256(ethers.toUtf8Bytes(spender + alertId + currentDate + currentMonth + currentYear));

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

  const uniqueKey = ethers.keccak256(
    ethers.toUtf8Bytes(receiver + txHash + alertId + currentDate + currentMonth + currentYear)
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
};

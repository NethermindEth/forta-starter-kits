const etherscanApis = {
  1: {
    urlContract: "https://api.etherscan.io/api?module=contract&action=getabi",
    urlAccount: "https://api.etherscan.io/api?module=account&action=txlist",
    urlAccountToken: "https://api.etherscan.io/api?module=account&action=tokentx",
    urlContractCreation: "https://api.etherscan.io/api?module=contract&action=getcontractcreation",
    urlLogs: "https://api.etherscan.io/api?module=logs&action=getLogs",
  },
  10: {
    urlContract: "https://api-optimistic.etherscan.io/api?module=contract&action=getabi",
    urlAccount: "https://api-optimistic.etherscan.io/api?module=account&action=txlist",
    urlAccountToken: "https://api-optimistic.etherscan.io/api?module=account&action=tokentx",
    urlContractCreation: "https://api-optimistic.etherscan.io/api?module=contract&action=getcontractcreation",
    urlLogs: "https://api-optimistic.etherscan.io/api?module=logs&action=getLogs",
  },
  56: {
    urlContract: "https://api.bscscan.com/api?module=contract&action=getabi",
    urlAccount: "https://api.bscscan.com/api?module=account&action=txlist",
    urlAccountToken: "https://api.bscscan.com/api?module=account&action=tokentx",
    urlContractCreation: "https://api.bscscan.com/api?module=contract&action=getcontractcreation",
    urlLogs: "https://api.bscscan.com/api?module=logs&action=getLogs",
  },
  137: {
    urlContract: "https://api.polygonscan.com/api?module=contract&action=getabi",
    urlAccount: "https://api.polygonscan.com/api?module=account&action=txlist",
    urlAccountToken: "https://api.polygonscan.com/api?module=account&action=tokentx",
    urlContractCreation: "https://api.polygonscan.com/api?module=contract&action=getcontractcreation",
    urlLogs: "https://api.polygonscan.com/api?module=logs&action=getLogs",
  },
  250: {
    urlContract: "https://api.ftmscan.com/api?module=contract&action=getabi",
    urlAccount: "https://api.ftmscan.com/api?module=account&action=txlist",
    urlAccountToken: "https://api.ftmscan.com/api?module=account&action=tokentx",
    urlContractCreation: "https://api.ftmscan.com/api?module=contract&action=getcontractcreation",
    urlLogs: "https://api.ftmscan.com/api?module=logs&action=getLogs",
  },
  8453: {
    urlContract: "https://api.basescan.org/api?module=contract&action=getabi",
    urlAccount: "https://api.basescan.org/api?module=account&action=txlist",
    urlAccountToken: "https://api.basescan.org/api?module=account&action=tokentx",
    urlContractCreation: "https://api.basescan.org/api?module=contract&action=getcontractcreation",
    urlLogs: "https://api.basescan.org/api?module=logs&action=getLogs",
  },
  42161: {
    urlContract: "https://api.arbiscan.io/api?module=contract&action=getabi",
    urlAccount: "https://api.arbiscan.io/api?module=account&action=txlist",
    urlAccountToken: "https://api.arbiscan.io/api?module=account&action=tokentx",
    urlContractCreation: "https://api.arbiscan.io/api?module=contract&action=getcontractcreation",
    urlLogs: "https://api.arbiscan.io/api?module=logs&action=getLogs",
  },
  43114: {
    urlContract: "https://api.snowtrace.io/api?module=contract&action=getabi",
    urlAccount: "https://api.snowtrace.io/api?module=account&action=txlist",
    urlAccountToken: "https://api.snowtrace.io/api?module=account&action=tokentx",
    urlContractCreation: "https://api.snowtrace.io/api?module=contract&action=getcontractcreation",
    urlLogs: "https://api.snowtrace.io/api?module=logs&action=getLogs",
  },
};

module.exports = {
  etherscanApis,
};

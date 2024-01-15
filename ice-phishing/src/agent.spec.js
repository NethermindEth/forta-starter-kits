const { FindingType, FindingSeverity, Finding, ethers, Label, EntityType } = require("forta-agent");
const axios = require("axios");
const { createAddress, createChecksumAddress } = require("forta-agent-tools");
const {
  provideHandleTransaction,
  provideHandleBlock,
  provideInitialize,
  getCachedAddresses,
  getCachedERC1155Tokens,
  resetLastTimestamp,
  resetInit,
  resetLastBlock,
  getSuspiciousContracts,
  initialize,
} = require("./agent");
const { STABLECOINS, CEX_ADDRESSES } = require("./utils");

const approveCountThreshold = 2;
const approveForAllCountThreshold = 2;
const transferCountThreshold = 2;
const timePeriodDays = 30;
const nonceThreshold = 100;
const maxAddressAlertsPerPeriod = 3;
const verifiedContractTxsThreshold = 1;
const pigButcheringTransferCountThreshold = 1;

const mockObjects = {
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

const spender = createAddress("0x01");
const spenderNewEOA = createAddress("0x332211");
const owner1 = createAddress("0x02");
const owner2 = createAddress("0x03");
const owner3 = createAddress("0x04");
const asset = createAddress("0x05");
const asset2 = createAddress("0x06");
const mockUniswapRouterV3 = createAddress("0x07");
const mockRecipient = createAddress("0x08");
const mockProxy = createAddress("0x09");
const mockImplementation = createAddress("0x10");

// Mock the config file
jest.mock(
  "../bot-config.json",
  () => ({
    approveCountThreshold,
    approveForAllCountThreshold,
    transferCountThreshold,
    timePeriodDays,
    nonceThreshold,
    verifiedContractTxsThreshold,
    pigButcheringTransferCountThreshold,
    maxAddressAlertsPerPeriod,
  }),
  { virtual: true }
);

const mockCalculateAlertRate = jest.fn();
const mockBalanceOf = jest.fn();
// Mock axios and ethers provider
jest.mock("axios");
jest.mock("forta-agent", () => {
  const original = jest.requireActual("forta-agent");
  return {
    ...original,
    ethers: {
      ...original.ethers,
      Contract: jest.fn().mockImplementation(() => ({
        balanceOf: mockBalanceOf,
      })),
    },
  };
});

const mockApprovalForAllEvent = [
  {
    address: asset,
    name: "ApprovalForAll",
    args: {
      owner: owner1,
      spender,
      approved: true,
    },
  },
  {
    address: asset,
    name: "ApprovalForAll",
    args: {
      owner: owner2,
      spender,
      approved: true,
    },
  },
  {
    address: asset,
    name: "ApprovalForAll",
    args: {
      owner: owner3,
      spender,
      approved: true,
    },
  },
];

const mockPermitFunctionCall = {
  address: asset,
  args: {
    owner: owner1,
    spender,
    deadline: 9359543534435,
    value: ethers.BigNumber.from(210),
  },
};

const mockDAILikePermitFunctionCall = {
  address: asset,
  args: {
    owner: owner1,
    spender,
    deadline: 8359543534435,
  },
};

const mockPermit2FunctionCall = {
  address: createAddress("0x06"),
  args: {
    owner: owner1,
    permitBatch: {
      details: [
        {
          token: asset,
          value: ethers.BigNumber.from(210),
          expiration: 9359543534435,
          nonce: 1,
        },
      ],
      spender,
      deadline: 9359543534435,
    },
    signature: ethers.utils.formatBytes32String("signature"),
  },
};

const mockPullFunctionCall = {
  address: mockUniswapRouterV3,
  args: {
    token: asset,
    value: ethers.BigNumber.from(210),
  },
};

const mockSweepTokenFunctionCall = {
  address: mockUniswapRouterV3,
  args: {
    token: asset,
    amountMinimum: ethers.BigNumber.from(210),
    recipient: mockRecipient,
  },
};

const mockUpgradedEvents = [
  {
    address: mockProxy,
    name: "Upgraded",
    args: {
      implementation: mockImplementation,
    },
  },
];

const mockApprovalERC20Events = [
  {
    address: asset,
    name: "Approval",
    args: {
      owner: owner1,
      spender,
      value: ethers.BigNumber.from(5),
    },
  },
  {
    address: asset,
    name: "Approval",
    args: {
      owner: owner2,
      spender,
      value: ethers.BigNumber.from(5),
    },
  },
  {
    address: asset,
    name: "Approval",
    args: {
      owner: owner3,
      spender,
      value: ethers.BigNumber.from(5),
    },
  },
  {
    address: asset,
    name: "Approval",
    args: {
      owner: createAddress("0x2211"),
      spender: spenderNewEOA, // New EOA
      value: ethers.BigNumber.from(5),
    },
  },
];

const mockApprovalERC721Events = [
  {
    address: asset,
    name: "Approval",
    args: {
      owner: owner1,
      spender,
      tokenId: ethers.BigNumber.from(5),
    },
  },
  {
    address: asset,
    name: "Approval",
    args: {
      owner: owner2,
      spender,
      tokenId: ethers.BigNumber.from(5),
    },
  },
  {
    address: asset,
    name: "Approval",
    args: {
      owner: owner3,
      spender,
      tokenId: ethers.BigNumber.from(5),
    },
  },
];

const mockTransferEvents = [
  {
    address: asset,
    name: "Transfer",
    args: {
      from: owner1,
      to: createAddress("0x11"),
      value: ethers.BigNumber.from(210),
    },
  },
  {
    address: asset,
    name: "Transfer",
    args: {
      from: owner2,
      value: ethers.BigNumber.from(1210),
    },
  },
  {
    address: asset,
    name: "Transfer",
    args: {
      from: owner3,
      value: ethers.BigNumber.from(11210),
    },
  },
];

const mockApprovalERC20Events2 = [
  {
    address: asset2,
    name: "Approval",
    args: {
      owner: owner1,
      spender,
      value: ethers.BigNumber.from(10000005),
    },
  },
  {
    address: asset2,
    name: "Approval",
    args: {
      owner: owner2,
      spender,
      value: ethers.BigNumber.from(10000005),
    },
  },
  {
    address: asset2,
    name: "Approval",
    args: {
      owner: owner3,
      spender,
      value: ethers.BigNumber.from(10000005),
    },
  },
];

const mockTransferEvents2 = [
  {
    address: asset2,
    name: "Transfer",
    args: {
      from: owner1,
      value: ethers.BigNumber.from(210),
    },
  },
  {
    address: asset2,
    name: "Transfer",
    args: {
      from: owner2,
      value: ethers.BigNumber.from(1210),
    },
  },
  {
    address: asset2,
    name: "Transfer",
    args: {
      from: owner3,
      value: ethers.BigNumber.from(11210),
    },
  },
];

const mockTransferERC721Events = [
  {
    address: asset,
    name: "Transfer",
    args: {
      from: owner1,
      tokenId: ethers.BigNumber.from(5),
    },
  },
  {
    address: asset,
    name: "Transfer",
    args: {
      from: owner2,
      tokenId: ethers.BigNumber.from(5),
    },
  },
  {
    address: asset,
    name: "Transfer",
    args: {
      from: owner3,
      tokenId: ethers.BigNumber.from(5),
    },
  },
];

const mockTransferSingleEvents = [
  {
    address: asset,
    name: "TransferSingle",
    args: {
      from: owner1,
      tokenId: ethers.BigNumber.from(5),
      value: ethers.BigNumber.from(1234),
    },
  },
  {
    address: asset,
    name: "TransferSingle",
    args: {
      from: owner2,
      tokenId: ethers.BigNumber.from(5),
      value: ethers.BigNumber.from(122234),
    },
  },
  {
    address: asset,
    name: "TransferSingle",
    args: {
      from: owner3,
      tokenId: ethers.BigNumber.from(5),
      value: ethers.BigNumber.from(1122234),
    },
  },
];

const mockTransferBatchEvents = [
  {
    address: asset,
    name: "TransferBatch",
    args: {
      from: owner1,
      tokenIds: [ethers.BigNumber.from(4), ethers.BigNumber.from(5)],
      values: [ethers.BigNumber.from(1234), ethers.BigNumber.from(1235)],
    },
  },
  {
    address: asset,
    name: "TransferBatch",
    args: {
      from: owner2,
      tokenIds: [ethers.BigNumber.from(4), ethers.BigNumber.from(5)],
      values: [ethers.BigNumber.from(111234), ethers.BigNumber.from(111235)],
    },
  },
  {
    address: asset,
    name: "TransferBatch",
    args: {
      from: owner3,
      tokenIds: [ethers.BigNumber.from(4), ethers.BigNumber.from(5)],
      values: [ethers.BigNumber.from(189234), ethers.BigNumber.from(189235)],
    },
  },
];

const mockPersistenceHelper = {
  persist: jest.fn(),
  load: jest.fn(),
};

const MOCK_DATABASE_KEYS = {
  totalUpgrades: "nm-icephishing-bot-total-upgrades-key",
  totalPermits: "nm-icephishing-bot-total-permits-key",
  totalApprovals: "nm-icephishing-bot-total-approvals-key",
  totalTransfers: "nm-icephishing-bot-total-transfers-key",
  totalERC20Approvals: "nm-icephishing-bot-total-erc20-approvals-key",
  totalERC721Approvals: "nm-icephishing-bot-total-erc721-approvals-key",
  totalERC721ApprovalsForAll: "nm-icephishing-bot-total-erc721-approvalsforall-key",
  totalERC1155ApprovalsForAll: "nm-icephishing-bot-total-erc1155-approvalsforall-key",
};

const MOCK_DATABASE_OBJECTS_KEY = {
  key: "test-nm-icephishing-bot-objects-v6-shard",
};

const mockCounters = {
  totalUpgrades: 10000,
  totalPermits: 60000,
  totalApprovals: 100000,
  totalTransfers: 65000,
  totalERC20Approvals: 72000,
  totalERC721Approvals: 10000,
  totalERC721ApprovalsForAll: 8200,
  totalERC1155ApprovalsForAll: 8000,
};

describe("ice-phishing bot", () => {
  const mockProvider = {
    getCode: jest.fn(),
    getBlockWithTransactions: jest.fn(),
    getTransactionCount: jest.fn(),
    getNetwork: jest.fn(),
  };
  const mockGetSuspiciousContracts = jest.fn();
  const mockGetNumberOfUniqueTxInitiators = jest.fn();
  let handleBlock;

  describe("provideHandleTransaction", () => {
    let mockTxEvent = {};
    let handleTransaction;

    beforeEach(() => {
      mockTxEvent = {
        filterLog: jest.fn(),
        filterFunction: jest.fn(),
        hash: "hash2",
        timestamp: 10000,
        from: spender,
        transaction: {
          data: "0x0",
        },
      };
      mockTxEvent.filterLog.mockReset();
      mockTxEvent.filterFunction.mockReset();
      mockProvider.getCode.mockReset();
      mockProvider.getTransactionCount.mockReset();
      mockProvider.getNetwork.mockReturnValue({ chainId: 1 });
      mockProvider.getBlockWithTransactions.mockReturnValue({ transactions: [{ hash: "hash15" }, { hash: "hash25" }] });
      mockGetNumberOfUniqueTxInitiators.mockResolvedValue(50);
      mockBalanceOf.mockReset();
      axios.get.mockReset();
      mockPersistenceHelper.load.mockReset();
      Object.keys(mockObjects).forEach((s) => {
        mockObjects[s] = {};
      });
      getCachedAddresses().clear();
      getCachedERC1155Tokens().clear();
      handleTransaction = provideHandleTransaction(
        mockProvider,
        mockCounters,
        MOCK_DATABASE_OBJECTS_KEY,
        mockPersistenceHelper,
        mockCalculateAlertRate,
        0,
        mockGetNumberOfUniqueTxInitiators
      );
    });

    it("should return empty findings if there are no Approval & Transfer events and no permit functions", async () => {
      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]); // ERC1155 transfers
      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      const findings = await handleTransaction(mockTxEvent);
      expect(findings).toStrictEqual([]);
      expect(mockTxEvent.filterLog).toHaveBeenCalledTimes(6);
      expect(mockTxEvent.filterFunction).toHaveBeenCalledTimes(5);
    });

    it("should return findings if there is a EIP-2612's permit function call", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      mockTxEvent.filterFunction
        .mockReturnValueOnce([mockPermitFunctionCall])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockTxEvent.filterLog.mockReturnValue([]);
      mockProvider.getCode.mockReturnValue("0x");
      mockCalculateAlertRate.mockReturnValueOnce("0.3");

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Account got permission for ERC-20 tokens",
          description: `${spender} gave permission to ${spender} for ${owner1}'s ERC-20 tokens`,
          alertId: "ICE-PHISHING-ERC20-PERMIT",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            msgSender: spender,
            owner: owner1,
            spender,
            anomalyScore: "0.3",
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
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Permit",
              confidence: 1,
            }),
          ],
        }),
      ]);
      expect(mockTxEvent.filterLog).toHaveBeenCalledTimes(6);
      expect(mockTxEvent.filterFunction).toHaveBeenCalledTimes(5);
    });

    it("should return findings if there is a DAI-like permit function call", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([mockDAILikePermitFunctionCall])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockTxEvent.filterLog.mockReturnValue([]);
      mockProvider.getCode.mockReturnValue("0x");
      mockCalculateAlertRate.mockReturnValueOnce("0.23");

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Account got permission for ERC-20 tokens",
          description: `${spender} gave permission to ${spender} for ${owner1}'s ERC-20 tokens`,
          alertId: "ICE-PHISHING-ERC20-PERMIT",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            msgSender: spender,
            owner: owner1,
            spender,
            anomalyScore: "0.23",
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
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Permit",
              confidence: 1,
            }),
          ],
        }),
      ]);
      expect(mockTxEvent.filterLog).toHaveBeenCalledTimes(6);
      expect(mockTxEvent.filterFunction).toHaveBeenCalledTimes(5);
    });

    it("should return findings if there is a Permit2 function call", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([mockPermit2FunctionCall])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockTxEvent.filterLog.mockReturnValue([]);
      mockProvider.getCode.mockReturnValue("0x");
      mockCalculateAlertRate.mockReturnValueOnce("0.3");

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Account got permission for ERC-20 tokens",
          description: `${spender} gave permission to ${spender} for ${owner1}'s ERC-20 tokens`,
          alertId: "ICE-PHISHING-ERC20-PERMIT",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            msgSender: spender,
            owner: owner1,
            spender,
            anomalyScore: "0.3",
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
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Permit",
              confidence: 1,
            }),
          ],
        }),
      ]);
      expect(mockTxEvent.filterLog).toHaveBeenCalledTimes(6);
      expect(mockTxEvent.filterFunction).toHaveBeenCalledTimes(5);
    });

    it("should return a finding if a suspicious contract is involved in a permit function call", async () => {
      const initialize = provideInitialize(
        mockProvider,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters,
        MOCK_DATABASE_OBJECTS_KEY
      );
      for (const key in MOCK_DATABASE_KEYS) {
        mockPersistenceHelper.load.mockReturnValueOnce(mockCounters[key]);
      }
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      await initialize();

      const mockBlockEvent = { block: { number: 876123 } };
      const date = new Date();
      const minutes = date.getMinutes();
      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        MOCK_DATABASE_OBJECTS_KEY,
        mockCounters,
        minutes // Passing minutes to make sure peristence is not triggered as minutes === lastExecutedMinute
      );

      mockGetSuspiciousContracts.mockResolvedValueOnce(
        new Set([{ address: createAddress("0xabcdabcd"), creator: createAddress("0xeeffeeff") }])
      );
      const axiosResponse = { data: [createAddress("0x5050")] };
      axios.get.mockResolvedValueOnce(axiosResponse);

      await handleBlock(mockBlockEvent);

      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      const mockTxEvent = {
        filterLog: jest.fn(),
        filterFunction: jest.fn(),
        hash: "hash2",
        timestamp: 1230000,
        blockNumber: 876123,
        from: createAddress("0x4567"),
      };

      const mockDAILikePermitFunctionCall = {
        address: asset,
        args: {
          owner: owner1,
          spender: createAddress("0xabcdabcd"),
          deadline: 8359543534435,
        },
      };

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([mockDAILikePermitFunctionCall])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockTxEvent.filterLog.mockReturnValue([]);

      mockProvider.getCode.mockResolvedValueOnce("0x32523523");
      const axiosResponse2 = {
        data: { message: "totally ok", status: "1", result: [{ contractCreator: createAddress("0xbbbb") }] },
      };
      const axiosResponse3 = { data: { message: "totally ok", status: "1", result: [createAddress("0xaaaa")] } };
      axios.get.mockResolvedValue(axiosResponse2).mockResolvedValueOnce(axiosResponse3);
      mockCalculateAlertRate.mockReturnValueOnce("0.023").mockReturnValueOnce("0.001");

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Suspicious contract (creator) was involved in an ERC-20 permission",
          description: `${createAddress("0x4567")} gave permission to ${createAddress(
            "0xabcdabcd"
          )} for ${owner1}'s ERC-20 tokens`,
          alertId: "ICE-PHISHING-ERC20-SUSPICIOUS-PERMIT",
          severity: FindingSeverity.Medium,
          type: FindingType.Suspicious,
          metadata: {
            msgSender: createAddress("0x4567"),
            owner: owner1,
            spender: createAddress("0xabcdabcd"),
            suspiciousContract: createAddress("0xabcdabcd"),
            suspiciousContractCreator: createAddress("0xeeffeeff"),
            anomalyScore: "0.023",
          },
          addresses: [asset],
          labels: [
            Label.fromObject({
              entity: createAddress("0xabcdabcd"),
              entityType: EntityType.Address,
              label: "Attacker",
              confidence: 0.5,
            }),
            Label.fromObject({
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Permit",
              confidence: 1,
            }),
          ],
        }),
        expect.objectContaining({
          name: "Account got permission for ERC-20 tokens",
          description: `${createAddress("0x4567")} gave permission to ${createAddress(
            "0xabcdabcd"
          )} for ${owner1}'s ERC-20 tokens`,
          alertId: "ICE-PHISHING-ERC20-PERMIT-INFO",
          severity: FindingSeverity.Info,
          type: FindingType.Info,
          metadata: {
            msgSender: createAddress("0x4567"),
            owner: owner1,
            spender: createAddress("0xabcdabcd"),
            anomalyScore: "0.001",
          },
          addresses: [asset],
          labels: [
            Label.fromObject({
              entity: createAddress("0xabcdabcd"),
              entityType: EntityType.Address,
              label: "Attacker",
              confidence: 0.2,
            }),
            Label.fromObject({
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Permit",
              confidence: 1,
            }),
          ],
        }),
      ]);
      expect(mockTxEvent.filterLog).toHaveBeenCalledTimes(7);
      expect(mockTxEvent.filterFunction).toHaveBeenCalledTimes(5);
    });

    it("should return a finding if a creator of a suspicious contract is involved in a permit function call", async () => {
      const initialize = provideInitialize(
        mockProvider,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters,
        MOCK_DATABASE_OBJECTS_KEY
      );
      for (const key in MOCK_DATABASE_KEYS) {
        mockPersistenceHelper.load.mockReturnValueOnce(mockCounters[key]);
      }
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      await initialize();

      const mockBlockEvent = { block: { number: 876126 } };
      const date = new Date();
      const minutes = date.getMinutes();
      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        MOCK_DATABASE_OBJECTS_KEY,
        mockCounters,
        minutes // Passing minutes to make sure peristence is not triggered as minutes === lastExecutedMinute
      );

      await handleBlock(mockBlockEvent);

      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      for (const key in MOCK_DATABASE_KEYS) {
        mockPersistenceHelper.load.mockReturnValueOnce(mockCounters[key]);
      }

      const mockTxEvent = {
        filterLog: jest.fn(),
        filterFunction: jest.fn(),
        hash: "hash2",
        timestamp: 1230000,
        blockNumber: 876126,
        from: createAddress("0x4567"),
      };

      const mockDAILikePermitFunctionCall = {
        address: asset,
        args: {
          owner: owner1,
          spender: createAddress("0xeeffeeff"),
          deadline: 8359543534435,
        },
      };

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([mockDAILikePermitFunctionCall])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockTxEvent.filterLog.mockReturnValue([]);

      mockProvider.getCode.mockResolvedValueOnce("0x32523523");
      const axiosResponse2 = {
        data: { message: "totally ok", status: "1", result: [{ contractCreator: createAddress("0xbbbb") }] },
      };
      const axiosResponse3 = { data: { message: "totally ok", status: "1", result: [createAddress("0xaaaa")] } };
      axios.get.mockResolvedValue(axiosResponse2).mockResolvedValueOnce(axiosResponse3);
      mockCalculateAlertRate.mockReturnValueOnce("0.1023").mockReturnValueOnce("0.1001");

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Suspicious contract (creator) was involved in an ERC-20 permission",
          description: `${createAddress("0x4567")} gave permission to ${createAddress(
            "0xeeffeeff"
          )} for ${owner1}'s ERC-20 tokens`,
          alertId: "ICE-PHISHING-ERC20-SUSPICIOUS-PERMIT",
          severity: FindingSeverity.Medium,
          type: FindingType.Suspicious,
          metadata: {
            msgSender: createAddress("0x4567"),
            owner: owner1,
            spender: createAddress("0xeeffeeff"),
            suspiciousContract: createAddress("0xabcdabcd"),
            suspiciousContractCreator: createAddress("0xeeffeeff"),
            anomalyScore: "0.1023",
          },
          addresses: [asset],
          labels: [
            Label.fromObject({
              entity: createAddress("0xeeffeeff"),
              entityType: EntityType.Address,
              label: "Attacker",
              confidence: 0.5,
            }),
            Label.fromObject({
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Permit",
              confidence: 1,
            }),
          ],
        }),
        expect.objectContaining({
          name: "Account got permission for ERC-20 tokens",
          description: `${createAddress("0x4567")} gave permission to ${createAddress(
            "0xeeffeeff"
          )} for ${owner1}'s ERC-20 tokens`,
          alertId: "ICE-PHISHING-ERC20-PERMIT-INFO",
          severity: FindingSeverity.Info,
          type: FindingType.Info,
          metadata: {
            msgSender: createAddress("0x4567"),
            owner: owner1,
            spender: createAddress("0xeeffeeff"),
            anomalyScore: "0.1001",
          },
          addresses: [asset],
          labels: [
            Label.fromObject({
              entity: createAddress("0xeeffeeff"),
              entityType: EntityType.Address,
              label: "Attacker",
              confidence: 0.2,
            }),
            Label.fromObject({
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Permit",
              confidence: 1,
            }),
          ],
        }),
      ]);
      expect(mockTxEvent.filterLog).toHaveBeenCalledTimes(7);
      expect(mockTxEvent.filterFunction).toHaveBeenCalledTimes(5);
    });

    it("should return findings if there is a high number of ERC1155 ApprovalForAll events", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      const tempTxEvent0 = {
        filterFunction: jest
          .fn()
          .mockReturnValueOnce([])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([]),
        filterLog: jest
          .fn()
          .mockReturnValueOnce([]) // ERC20 approvals
          .mockReturnValueOnce([]) // ERC721 approvals
          .mockReturnValueOnce([mockApprovalForAllEvent[0]]) // ApprovalForAll
          .mockReturnValueOnce([]) // ERC20 transfers
          .mockReturnValueOnce([]) // ERC721 transfers
          .mockReturnValueOnce([]) // ERC1155 transfers
          .mockReturnValueOnce([]), // Upgrades
        hash: "hash0",
        timestamp: 0,
        from: spender,
      };
      mockProvider.getCode.mockReturnValueOnce("0x992eb2c2d699").mockReturnValueOnce("0x").mockReturnValueOnce("0x");
      mockProvider.getTransactionCount.mockReturnValue(1);
      await handleTransaction(tempTxEvent0);

      expect(mockProvider.getCode).toHaveBeenCalledTimes(3);

      const tempTxEvent1 = {
        filterFunction: jest
          .fn()
          .mockReturnValueOnce([])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([]),
        filterLog: jest
          .fn()
          .mockReturnValueOnce([]) // ERC20 approvals
          .mockReturnValueOnce([]) // ERC721 approvals
          .mockReturnValueOnce([mockApprovalForAllEvent[1]]) // ApprovalForAll
          .mockReturnValueOnce([]) // ERC20 transfers
          .mockReturnValueOnce([]) // ERC721 transfers
          .mockReturnValueOnce([]) // ERC1155 transfers
          .mockReturnValueOnce([]), // Upgrades
        hash: "hash1",
        timestamp: 1000,
        from: spender,
      };
      mockProvider.getCode.mockReturnValueOnce("0x");
      mockProvider.getTransactionCount.mockReturnValue(1);
      await handleTransaction(tempTxEvent1);

      expect(mockProvider.getCode).toHaveBeenCalledTimes(4);
      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([mockApprovalForAllEvent[2]]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]) // ERC1155 transfers
        .mockReturnValueOnce([]); // Upgrades

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockProvider.getCode.mockReturnValueOnce("0x");
      mockProvider.getTransactionCount.mockReturnValue(1);
      expect(mockProvider.getCode).toHaveBeenCalledTimes(4);
      mockCalculateAlertRate.mockReturnValueOnce("0.91023");

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Account got approval for all ERC-1155 tokens",
          description: `${spender} obtained transfer approval for all ERC-1155 tokens from ${owner3}`,
          alertId: "ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            spender,
            owner: owner3,
            anomalyScore: "0.91023",
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
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Approval",
              confidence: 1,
            }),
          ],
        }),
      ]);
    });

    it("should return findings if there is a high number of ERC721 ApprovalForAll events", async () => {
      const initialize = provideInitialize(
        mockProvider,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters,
        MOCK_DATABASE_OBJECTS_KEY
      );
      for (const key in MOCK_DATABASE_KEYS) {
        mockPersistenceHelper.load.mockReturnValueOnce(mockCounters[key]);
      }
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      await initialize();

      for (let i = 0; i < 2; i++) {
        const tempTxEvent = {
          filterFunction: jest
            .fn()
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([mockApprovalForAllEvent[i]]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]) // ERC1155 transfers
            .mockReturnValueOnce([]), // Upgrades
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
        };
        mockProvider.getCode.mockReturnValue("0x");

        mockProvider.getTransactionCount.mockReturnValue(1);
        await handleTransaction(tempTxEvent);
      }

      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([mockApprovalForAllEvent[2]]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]) // ERC1155 transfers
        .mockReturnValueOnce([]); // Upgrades

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockProvider.getCode.mockReturnValue("0x");
      mockProvider.getTransactionCount.mockReturnValue(1);
      mockCalculateAlertRate.mockReturnValueOnce("0.891023");

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Account got approval for all ERC-721 tokens",
          description: `${spender} obtained transfer approval for all ERC-721 tokens from ${owner3}`,
          alertId: "ICE-PHISHING-ERC721-APPROVAL-FOR-ALL",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            spender,
            owner: owner3,
            anomalyScore: "0.891023",
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
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Approval",
              confidence: 1,
            }),
          ],
        }),
      ]);
    });

    it("should return findings if there is a high number of ERC721 ApprovalForAll events regarding a high nonce EOA", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      const thisMockApprovalForAllEvent = [
        {
          address: asset,
          name: "ApprovalForAll",
          args: {
            owner: createAddress("0xaacdcd"),
            spender: createAddress("0xcdcd"),
            approved: true,
          },
        },
        {
          address: asset,
          name: "ApprovalForAll",
          args: {
            owner: createAddress("0xbbcdcd"),
            spender: createAddress("0xcdcd"),
            approved: true,
          },
        },
        {
          address: asset,
          name: "ApprovalForAll",
          args: {
            owner: createAddress("0xcccdcd"),
            spender: createAddress("0xcdcd"),
            approved: true,
          },
        },
      ];
      for (let i = 0; i < 2; i++) {
        const tempTxEvent = {
          filterFunction: jest
            .fn()
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([thisMockApprovalForAllEvent[i]]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]) // ERC1155 transfers
            .mockReturnValueOnce([]), // Upgrades
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
        };
        mockProvider.getCode.mockReturnValue("0x");
        mockProvider.getTransactionCount.mockReturnValueOnce(1234454).mockReturnValueOnce(1234454);
        await handleTransaction(tempTxEvent);
      }

      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([thisMockApprovalForAllEvent[2]]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]) // ERC1155 transfers
        .mockReturnValueOnce([]); // Upgrades

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockProvider.getCode.mockReturnValue("0x");
      mockProvider.getTransactionCount.mockReturnValue(1234454);
      expect(mockProvider.getCode).toHaveBeenCalledTimes(4);
      mockCalculateAlertRate.mockReturnValueOnce("0.8910234");

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Account got approval for all ERC-721 tokens",
          description: `${createAddress(
            "0xcdcd"
          )} obtained transfer approval for all ERC-721 tokens from ${createAddress("0xcccdcd")}`,
          alertId: "ICE-PHISHING-ERC721-APPROVAL-FOR-ALL-INFO",
          severity: FindingSeverity.Info,
          type: FindingType.Info,
          metadata: {
            spender: createAddress("0xcdcd"),
            owner: createAddress("0xcccdcd"),
            anomalyScore: "0.8910234",
          },
          addresses: [asset],
          labels: [
            Label.fromObject({
              entity: createAddress("0xcdcd"),
              entityType: EntityType.Address,
              label: "Attacker",
              confidence: 0.15,
            }),
            Label.fromObject({
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Approval",
              confidence: 1,
            }),
          ],
        }),
      ]);
    });

    it("should return findings if there is a high number of ERC20 Approval events", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      for (let i = 0; i < 2; i++) {
        const tempTxEvent = {
          filterFunction: jest
            .fn()
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([mockApprovalERC20Events[i]]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]) // ERC1155 transfers
            .mockReturnValueOnce([]), // Upgrades
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
        };
        mockProvider.getCode.mockReturnValue("0x");

        await handleTransaction(tempTxEvent);
      }

      mockTxEvent.filterLog
        .mockReturnValueOnce([mockApprovalERC20Events[2]]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]) // ERC1155 transfers
        .mockReturnValueOnce([]); // Upgrades

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockProvider.getCode.mockReturnValue("0x");
      expect(mockProvider.getCode).toHaveBeenCalledTimes(3);
      const axiosResponse = {
        data: {
          message: "totally ok",
          status: "1",
          result: [],
        },
      };
      axios.get.mockResolvedValueOnce(axiosResponse);
      mockCalculateAlertRate.mockReturnValueOnce("0.08910234");
      const alertId = "ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS";
      const now = new Date();
      const currentDate = now.getDate();
      const currentMonth = now.getMonth() + 1;
      const currentYear = now.getFullYear();

      const uniqueKey = ethers.utils.keccak256(
        ethers.utils.toUtf8Bytes(spender + alertId + currentDate + currentMonth + currentYear)
      );
      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "High number of accounts granted approvals for ERC-20 tokens",
          description: `${spender} obtained transfer approval for 1 ERC-20 tokens by 3 accounts over period of 1 days.`,
          alertId: "ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            firstTxHash: "hash0",
            lastTxHash: "hash2",
            anomalyScore: "0.08910234",
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
              entity: "hash0",
              entityType: EntityType.Transaction,
              label: "Approval",
              confidence: 1,
            }),
            Label.fromObject({
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Approval",
              confidence: 1,
            }),
          ],
          uniqueKey,
        }),
      ]);
    });

    it("should not return findings if there is a high number of ERC20 Approval events but there have been more than once interactions between the victim and the attacker", async () => {
      const initialize = provideInitialize(
        mockProvider,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters,
        MOCK_DATABASE_OBJECTS_KEY
      );
      for (const key in MOCK_DATABASE_KEYS) {
        mockPersistenceHelper.load.mockReturnValueOnce(mockCounters[key]);
      }
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);
      await initialize();

      for (let i = 0; i < 2; i++) {
        const tempTxEvent = {
          filterFunction: jest
            .fn()
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([mockApprovalERC20Events[i]]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]) // ERC1155 transfers
            .mockReturnValueOnce([]), // Upgrades
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
        };
        mockProvider.getCode.mockReturnValue("0x");

        await handleTransaction(tempTxEvent);
      }

      // Two interactions
      const axiosResponse = {
        data: {
          message: "totally ok",
          status: "1",
          result: [
            { from: spender, to: asset, input: owner1.replace(/^0x/, "") },
            { from: spender, to: asset, input: owner1.replace(/^0x/, "") },
          ],
        },
      };
      axios.get.mockResolvedValueOnce(axiosResponse);
      mockTxEvent.filterLog
        .mockReturnValueOnce([mockApprovalERC20Events[2]]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]) // ERC1155 transfers
        .mockReturnValueOnce([]); // Upgrades

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockProvider.getCode.mockReturnValue("0x");
      expect(mockProvider.getCode).toHaveBeenCalledTimes(3);

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([]);
    });

    it("should return findings if there is a high number of ERC721 Approval events", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      for (let i = 0; i < 2; i++) {
        const tempTxEvent = {
          filterFunction: jest
            .fn()
            .mockReturnValue([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([mockApprovalERC721Events[i]]) // ERC721 approvals
            .mockReturnValue([]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]) // ERC1155 transfers
            .mockReturnValueOnce([]), // Upgrades
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
        };
        mockProvider.getCode.mockReturnValue("0x");
        await handleTransaction(tempTxEvent);
      }

      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([mockApprovalERC721Events[2]]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]) // ERC1155 transfers
        .mockReturnValueOnce([]); // Upgrades

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockCalculateAlertRate.mockReturnValueOnce("0.008910234");

      const alertId = "ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS";
      const now = new Date();
      const currentDate = now.getDate();
      const currentMonth = now.getMonth() + 1;
      const currentYear = now.getFullYear();

      const uniqueKey = ethers.utils.keccak256(
        ethers.utils.toUtf8Bytes(spender + alertId + currentDate + currentMonth + currentYear)
      );

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "High number of accounts granted approvals for ERC-721 tokens",
          description: `${spender} obtained transfer approval for 1 ERC-721 tokens by 3 accounts over period of 1 days.`,
          alertId,
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            firstTxHash: "hash0",
            lastTxHash: "hash2",
            anomalyScore: "0.008910234",
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
              entity: "hash0",
              entityType: EntityType.Transaction,
              label: "Approval",
              confidence: 1,
            }),
            Label.fromObject({
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Approval",
              confidence: 1,
            }),
          ],
          uniqueKey,
        }),
      ]);
    });

    it("should return findings if there is a high number of ERC721 Approval events regarding a verified contract", async () => {
      const initialize = provideInitialize(
        mockProvider,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters,
        MOCK_DATABASE_OBJECTS_KEY
      );
      for (const key in MOCK_DATABASE_KEYS) {
        mockPersistenceHelper.load.mockReturnValueOnce(mockCounters[key]);
      }
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);
      await initialize();

      const spender = createAddress("0xeded");

      resetLastBlock();
      const axiosResponse2 = { data: { "www.scamDomain.com": [createAddress("0x5050")] } };
      axios.get.mockResolvedValueOnce(axiosResponse2);
      const thisMockApprovalERC721Events = [
        {
          address: asset,
          name: "Approval",
          args: {
            owner: owner1,
            spender,
            tokenId: ethers.BigNumber.from(5),
          },
        },
        {
          address: asset,
          name: "Approval",
          args: {
            owner: owner2,
            spender,
            tokenId: ethers.BigNumber.from(5),
          },
        },
        {
          address: asset,
          name: "Approval",
          args: {
            owner: owner3,
            spender,
            tokenId: ethers.BigNumber.from(5),
          },
        },
      ];

      for (let i = 0; i < 3; i++) {
        const tempTxEvent = {
          filterFunction: jest
            .fn()
            .mockReturnValue([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([thisMockApprovalERC721Events[i]]) // ERC721 approvals
            .mockReturnValue([]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]) // ERC1155 transfers
            .mockReturnValueOnce([]), // Upgrades
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
          blockNumber: 23,
        };
        const axiosResponse = { data: { message: "completely Ok", status: "1", result: [] } };
        const axiosResponse2 = {
          data: { message: "completely ok", result: [{ contractCreator: createAddress("0x77777") }] },
        };
        axios.get
          .mockResolvedValueOnce(axiosResponse)
          .mockResolvedValueOnce(axiosResponse2)
          .mockResolvedValueOnce(axiosResponse2);

        mockProvider.getCode.mockReturnValueOnce("0x").mockReturnValueOnce("0xa342a");
        await handleTransaction(tempTxEvent);
      }
      mockTxEvent.blockNumber = 23;
      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([thisMockApprovalERC721Events[2]]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]) // ERC1155 transfers
        .mockReturnValueOnce([]); // Upgrades

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockCalculateAlertRate.mockReturnValueOnce("0.0008910234");
      const alertId = "ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS-INFO";
      const now = new Date();
      const currentDate = now.getDate();
      const currentMonth = now.getMonth() + 1;
      const currentYear = now.getFullYear();

      const uniqueKey = ethers.utils.keccak256(
        ethers.utils.toUtf8Bytes(spender + alertId + currentDate + currentMonth + currentYear)
      );

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "High number of accounts granted approvals for ERC-721 tokens",
          description: `${spender} obtained transfer approval for 1 ERC-721 tokens by 3 accounts over period of 1 days.`,
          alertId,
          severity: FindingSeverity.Info,
          type: FindingType.Info,
          metadata: {
            firstTxHash: "hash0",
            lastTxHash: "hash2",
            anomalyScore: "0.0008910234",
          },
          addresses: [asset],
          labels: [
            Label.fromObject({
              entity: spender,
              entityType: EntityType.Address,
              label: "Attacker",
              confidence: 0.25,
            }),
            Label.fromObject({
              entity: "hash0",
              entityType: EntityType.Transaction,
              label: "Approval",
              confidence: 1,
            }),
            Label.fromObject({
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Approval",
              confidence: 1,
            }),
          ],
          uniqueKey,
        }),
      ]);
    });

    it("should not return findings if there is a high number of ERC721 Approval events regarding a verified contract with high number of past transactions", async () => {
      const initialize = provideInitialize(
        mockProvider,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters,
        MOCK_DATABASE_OBJECTS_KEY
      );
      for (const key in MOCK_DATABASE_KEYS) {
        mockPersistenceHelper.load.mockReturnValueOnce(mockCounters[key]);
      }

      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      await initialize();
      const spender = createAddress("0xabeded");
      const thisMockApprovalERC721Events = [
        {
          address: asset,
          name: "Approval",
          args: {
            owner: owner1,
            spender,
            tokenId: ethers.BigNumber.from(5),
          },
        },
        {
          address: asset,
          name: "Approval",
          args: {
            owner: owner2,
            spender,
            tokenId: ethers.BigNumber.from(5),
          },
        },
        {
          address: asset,
          name: "Approval",
          args: {
            owner: owner3,
            spender,
            tokenId: ethers.BigNumber.from(5),
          },
        },
      ];

      for (let i = 0; i < 3; i++) {
        const tempTxEvent = {
          filterFunction: jest
            .fn()
            .mockReturnValue([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([thisMockApprovalERC721Events[i]]) // ERC721 approvals
            .mockReturnValue([]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]) // ERC1155 transfers
            .mockReturnValueOnce([]), // Upgrades
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
        };
        const axiosResponse = { data: { message: "completely Ok", status: "1", result: ["result1", "result2"] } }; // high number of txs
        const axiosResponse3 = {
          data: { message: "completely ok", result: [{ contractCreator: createAddress("0x77777") }] },
        };
        axios.get
          .mockResolvedValueOnce(axiosResponse)
          .mockResolvedValueOnce(axiosResponse)
          .mockResolvedValueOnce(axiosResponse3)
          .mockResolvedValueOnce(axiosResponse3);

        mockProvider.getCode.mockReturnValueOnce("0x").mockReturnValueOnce("0xa342a");
        await handleTransaction(tempTxEvent);
      }

      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([thisMockApprovalERC721Events[2]]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]) // ERC1155 transfers
        .mockReturnValueOnce([]); // Upgrades

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);

      const findings = await handleTransaction(mockTxEvent);
      expect(findings).toStrictEqual([]);
    });

    it("should return findings if there is a high number of ERC-20 Transfer events and the balance is completely drained", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      // Create the Approval events first
      for (let i = 0; i < 3; i++) {
        const tempTxEvent = {
          filterFunction: jest
            .fn()
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([mockApprovalERC20Events[i]]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]) // ERC1155 transfers
            .mockReturnValueOnce([]), // Upgrades
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
        };
        mockProvider.getCode.mockReturnValue("0x");
        if (i === 2) {
          const axiosResponse = {
            data: {
              message: "totally ok",
              status: "1",
              result: [],
            },
          };
          axios.get.mockResolvedValueOnce(axiosResponse);
          mockCalculateAlertRate.mockReturnValueOnce(0.0008910231);
        }
        await handleTransaction(tempTxEvent);
      }

      for (let i = 0; i < 2; i++) {
        const tempTxEvent = {
          filterFunction: jest
            .fn()
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([mockApprovalERC20Events[i]]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([]) // ApprovalForAll
            .mockReturnValueOnce([mockTransferEvents[i]]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]) // ERC1155 transfers
            .mockReturnValueOnce([]), // Upgrades
          hash: `hash${i}`,
          timestamp: 3000 + 1000 * i,
          from: spender,
          transaction: {
            data: "0x0",
          },
        };

        await handleTransaction(tempTxEvent);
      }

      mockTxEvent.filterLog
        .mockReturnValueOnce([mockApprovalERC20Events[2]]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([mockTransferEvents[2]]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]) // ERC1155 transfers
        .mockReturnValueOnce([]); // Upgrades

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockBalanceOf.mockResolvedValueOnce(ethers.BigNumber.from(0));
      mockCalculateAlertRate.mockReturnValueOnce(0.4);

      const alertId = "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS";
      const now = new Date();
      const currentDate = now.getDate();
      const currentMonth = now.getMonth() + 1;
      const currentYear = now.getFullYear();

      const uniqueKey = ethers.utils.keccak256(
        ethers.utils.toUtf8Bytes(spender + alertId + currentDate + currentMonth + currentYear)
      );

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Previously approved assets transferred",
          description: `${spender} transferred 1 assets from 3 accounts over period of 1 days.`,
          alertId,
          severity: FindingSeverity.High,
          type: FindingType.Exploit,
          metadata: {
            firstTxHash: "hash0",
            lastTxHash: "hash2",
            anomalyScore: "0.4",
          },
          addresses: [asset],
          labels: [
            Label.fromObject({
              entity: spender,
              entityType: EntityType.Address,
              label: "Attacker",
              confidence: 0.4,
            }),
            Label.fromObject({
              entity: "hash0",
              entityType: EntityType.Transaction,
              label: "Transfer",
              confidence: 1,
            }),
            Label.fromObject({
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Transfer",
              confidence: 1,
            }),
          ],
          uniqueKey,
        }),
      ]);
    });

    it("should not return findings if there is a high number of ERC-20 Transfer events but the balance is not completely drained", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);
      const axiosResponse = {
        data: {
          message: "totally ok",
          status: "1",
          result: [],
        },
      };

      // Create the Approval events first
      for (let i = 0; i < 3; i++) {
        const tempTxEvent = {
          filterFunction: jest
            .fn()
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([mockApprovalERC20Events2[i]]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]) // ERC1155 transfers
            .mockReturnValueOnce([]), // Upgrades
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
        };
        mockProvider.getCode.mockReturnValue("0x");
        if (i === 2) {
          axios.get.mockResolvedValueOnce(axiosResponse);
          mockCalculateAlertRate.mockReturnValueOnce(0.10008910231);
        }

        await handleTransaction(tempTxEvent);
      }

      for (let i = 0; i < 2; i++) {
        const tempTxEvent = {
          filterFunction: jest
            .fn()
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([mockApprovalERC20Events2[i]]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([]) // ApprovalForAll
            .mockReturnValueOnce([mockTransferEvents2[i]]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]) // ERC1155 transfers
            .mockReturnValueOnce([]), // Upgrades
          hash: `hash${i}`,
          timestamp: 3000 + 1000 * i,
          from: spender,
          transaction: {
            data: "0x0",
          },
        };
        mockBalanceOf
          .mockResolvedValue(ethers.BigNumber.from("100000000000000"))
          .mockResolvedValue(ethers.BigNumber.from("100000000000000")); // not drained
        await handleTransaction(tempTxEvent);
      }

      mockTxEvent.filterLog
        .mockReturnValueOnce([mockApprovalERC20Events2[2]]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([mockTransferEvents2[2]]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]) // ERC1155 transfers
        .mockReturnValueOnce([]); // Upgrades

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockBalanceOf.mockResolvedValue(ethers.BigNumber.from("100000000000000")); // not drained
      expect(mockProvider.getCode).toHaveBeenCalledTimes(4);

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([]);
    });

    it("should return findings if there is a high number of ERC-721 Transfer events", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);
      const axiosResponse = {
        data: {
          message: "totally ok",
          status: "1",
          result: [],
        },
      };

      // Create the Approval events first
      for (let i = 0; i < 3; i++) {
        const tempTxEvent = {
          filterFunction: jest
            .fn()
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([mockApprovalERC721Events[i]]) // ERC721 approvals
            .mockReturnValueOnce([]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]) // ERC1155 transfers
            .mockReturnValueOnce([]), // Upgrades
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
        };
        mockProvider.getCode.mockReturnValue("0x");
        if (i === 2) {
          // axios.get.mockResolvedValueOnce(axiosResponse);
          mockCalculateAlertRate.mockReturnValueOnce(0.914);
        }
        await handleTransaction(tempTxEvent);
      }

      for (let i = 0; i < 2; i++) {
        const tempTxEvent = {
          filterFunction: jest
            .fn()
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([mockApprovalERC721Events[i]]) // ERC721 approvals
            .mockReturnValueOnce([]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([mockTransferERC721Events[i]]) // ERC721 transfers
            .mockReturnValueOnce([]) // ERC1155 transfers
            .mockReturnValueOnce([]), // Upgrades
          hash: `hash${i}`,
          timestamp: 3000 + 1000 * i,
          from: spender,
          transaction: {
            data: "0x0",
          },
        };
        if (i === 0) {
          axios.get.mockResolvedValueOnce(axiosResponse);
          mockCalculateAlertRate.mockReturnValueOnce(0.9148);
        }
        await handleTransaction(tempTxEvent);
      }

      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([mockApprovalERC721Events[2]]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([mockTransferERC721Events[2]]) // ERC721 transfers
        .mockReturnValueOnce([]) // ERC1155 transfers
        .mockReturnValueOnce([]); // Upgrades

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      expect(mockProvider.getCode).toHaveBeenCalledTimes(4);
      mockCalculateAlertRate.mockReturnValueOnce(0.42);

      const alertId = "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS";
      const now = new Date();
      const currentDate = now.getDate();
      const currentMonth = now.getMonth() + 1;
      const currentYear = now.getFullYear();

      const uniqueKey = ethers.utils.keccak256(
        ethers.utils.toUtf8Bytes(spender + alertId + currentDate + currentMonth + currentYear)
      );

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Previously approved assets transferred",
          description: `${spender} transferred 1 assets from 3 accounts over period of 1 days.`,
          alertId,
          severity: FindingSeverity.High,
          type: FindingType.Exploit,
          metadata: {
            firstTxHash: "hash0",
            lastTxHash: "hash2",
            anomalyScore: "0.42",
          },
          addresses: [asset],
          labels: [
            Label.fromObject({
              entity: spender,
              entityType: EntityType.Address,
              label: "Attacker",
              confidence: 0.4,
            }),
            Label.fromObject({
              entity: "hash0",
              entityType: EntityType.Transaction,
              label: "Transfer",
              confidence: 1,
            }),
            Label.fromObject({
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Transfer",
              confidence: 1,
            }),
            Label.fromObject({
              entity: "5,0x0000000000000000000000000000000000000005",
              entityType: EntityType.Address,
              label: "NFT",
              confidence: 1,
            }),
          ],
          uniqueKey,
        }),
      ]);
    });

    it("should return findings if there is a high number of ERC-1155 TransferSingle events and the balance is completely drained", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      // Create the Approval events first
      for (let i = 0; i < 3; i++) {
        const tempTxEvent = {
          filterFunction: jest
            .fn()
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([mockApprovalForAllEvent[i]]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]) // ERC1155 transfers
            .mockReturnValueOnce([]), // Upgrades
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
        };
        // First call includes 1155 sig "2eb2c2d6"
        mockProvider.getCode.mockReturnValueOnce("0x992eb2c2d699").mockReturnValue("0x");
        await handleTransaction(tempTxEvent);
      }

      for (let i = 0; i < 2; i++) {
        const tempTxEvent = {
          filterFunction: jest
            .fn()
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([mockApprovalForAllEvent[i]]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([mockTransferSingleEvents[i]]) // ERC1155 transfers
            .mockReturnValueOnce([]), // Upgrades
          hash: `hash${i}`,
          timestamp: 3000 + 1000 * i,
          from: spender,
          transaction: {
            data: "0x0",
          },
        };
        await handleTransaction(tempTxEvent);
      }

      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([mockApprovalForAllEvent[2]]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([mockTransferSingleEvents[2]]) // ERC1155 transfers
        .mockReturnValueOnce([]); // Upgrades

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockBalanceOf.mockResolvedValueOnce(ethers.BigNumber.from(0));
      expect(mockProvider.getCode).toHaveBeenCalledTimes(6);
      mockCalculateAlertRate.mockReturnValueOnce(0.421).mockReturnValueOnce(0.1421);

      const alertId = "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS";
      const now = new Date();
      const currentDate = now.getDate();
      const currentMonth = now.getMonth() + 1;
      const currentYear = now.getFullYear();

      const uniqueKey = ethers.utils.keccak256(
        ethers.utils.toUtf8Bytes(spender + alertId + currentDate + currentMonth + currentYear)
      );

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Account got approval for all ERC-1155 tokens",
          description: `${spender} obtained transfer approval for all ERC-1155 tokens from ${owner3}`,
          alertId: "ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            spender,
            owner: owner3,
            anomalyScore: "0.421",
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
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Approval",
              confidence: 1,
            }),
          ],
        }),
        expect.objectContaining({
          name: "Previously approved assets transferred",
          description: `${spender} transferred 1 assets from 3 accounts over period of 1 days.`,
          alertId,
          severity: FindingSeverity.High,
          type: FindingType.Exploit,
          metadata: {
            firstTxHash: "hash0",
            lastTxHash: "hash2",
            anomalyScore: "0.1421",
          },
          addresses: [asset],
          labels: [
            Label.fromObject({
              entity: spender,
              entityType: EntityType.Address,
              label: "Attacker",
              confidence: 0.4,
            }),
            Label.fromObject({
              entity: "hash0",
              entityType: EntityType.Transaction,
              label: "Transfer",
              confidence: 1,
            }),
            Label.fromObject({
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Transfer",
              confidence: 1,
            }),
            Label.fromObject({
              entity: "5,0x0000000000000000000000000000000000000005",
              entityType: EntityType.Address,
              label: "NFT",
              confidence: 1,
            }),
          ],
          uniqueKey,
        }),
      ]);
    });

    it("should return findings if there is a high number of ERC-1155 TransferBatch events and the balance is completely drained", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      // Create the Approval events first
      for (let i = 0; i < 3; i++) {
        const tempTxEvent = {
          filterFunction: jest
            .fn()
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([mockApprovalForAllEvent[i]]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]) // ERC1155 transfers
            .mockReturnValueOnce([]), // Upgrades
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
        };
        mockProvider.getCode.mockReturnValueOnce("0x992eb2c2d699").mockReturnValue("0x");

        await handleTransaction(tempTxEvent);
      }

      for (let i = 0; i < 2; i++) {
        const tempTxEvent = {
          filterFunction: jest
            .fn()
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([mockApprovalForAllEvent[i]]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([mockTransferBatchEvents[i]]) // ERC1155 transfers
            .mockReturnValueOnce([]), // Upgrades
          hash: `hash${i}`,
          timestamp: 3000 + 1000 * i,
          from: spender,
          transaction: {
            data: "0x0",
          },
        };

        await handleTransaction(tempTxEvent);
      }

      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([mockApprovalForAllEvent[2]]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([mockTransferBatchEvents[2]]) // ERC1155 transfers
        .mockReturnValueOnce([]); // Upgrades

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockBalanceOf.mockResolvedValue(ethers.BigNumber.from(0));
      expect(mockProvider.getCode).toHaveBeenCalledTimes(6);
      mockCalculateAlertRate.mockReturnValueOnce(0.212421).mockReturnValueOnce(0.1212);

      const alertId = "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS";
      const now = new Date();
      const currentDate = now.getDate();
      const currentMonth = now.getMonth() + 1;
      const currentYear = now.getFullYear();

      const uniqueKey = ethers.utils.keccak256(
        ethers.utils.toUtf8Bytes(spender + alertId + currentDate + currentMonth + currentYear)
      );

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Account got approval for all ERC-1155 tokens",
          description: `${spender} obtained transfer approval for all ERC-1155 tokens from ${owner3}`,
          alertId: "ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            spender,
            owner: owner3,
            anomalyScore: "0.212421",
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
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Approval",
              confidence: 1,
            }),
          ],
        }),

        expect.objectContaining({
          name: "Previously approved assets transferred",
          description: `${spender} transferred 1 assets from 3 accounts over period of 1 days.`,
          alertId,
          severity: FindingSeverity.High,
          type: FindingType.Exploit,
          metadata: {
            firstTxHash: "hash0",
            lastTxHash: "hash2",
            anomalyScore: "0.1212",
          },
          addresses: [asset],
          labels: [
            Label.fromObject({
              entity: spender,
              entityType: EntityType.Address,
              label: "Attacker",
              confidence: 0.4,
            }),
            Label.fromObject({
              entity: "hash0",
              entityType: EntityType.Transaction,
              label: "Transfer",
              confidence: 1,
            }),
            Label.fromObject({
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Transfer",
              confidence: 1,
            }),
            Label.fromObject({
              entity: "4,0x0000000000000000000000000000000000000005",
              entityType: EntityType.Address,
              label: "NFT",
              confidence: 1,
            }),
            Label.fromObject({
              entity: "5,0x0000000000000000000000000000000000000005",
              entityType: EntityType.Address,
              label: "NFT",
              confidence: 1,
            }),
          ],
          uniqueKey,
        }),
      ]);
    });

    it("should return a lower severity finding if there is a high number of ERC-1155 TransferBatch events when the balance is completely drained and the spender is a high nonce EOA", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      // Create the Approval events first
      const spender = createAddress("0x9831");
      const mockApprovalForAllEvent = [
        {
          address: asset,
          name: "ApprovalForAll",
          args: {
            owner: owner1,
            spender,
            approved: true,
          },
        },
        {
          address: asset,
          name: "ApprovalForAll",
          args: {
            owner: owner2,
            spender,
            approved: true,
          },
        },
        {
          address: asset,
          name: "ApprovalForAll",
          args: {
            owner: owner3,
            spender,
            approved: true,
          },
        },
      ];
      for (let i = 0; i < 3; i++) {
        const tempTxEvent = {
          filterFunction: jest
            .fn()
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([mockApprovalForAllEvent[i]]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]) // ERC1155 transfers
            .mockReturnValueOnce([]), // Upgrades
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
        };
        mockProvider.getCode.mockReturnValueOnce("0x992eb2c2d699").mockReturnValue("0x");
        mockProvider.getTransactionCount.mockReturnValue(123);
        await handleTransaction(tempTxEvent);
      }

      for (let i = 0; i < 2; i++) {
        const tempTxEvent = {
          filterFunction: jest
            .fn()
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([])
            .mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([mockApprovalForAllEvent[i]]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([mockTransferBatchEvents[i]]) // ERC1155 transfers
            .mockReturnValueOnce([]), // Upgrades
          hash: `hash${i}`,
          timestamp: 3000 + 1000 * i,
          from: spender,
          transaction: {
            data: "0x0",
          },
        };
        if (i == 1) mockCalculateAlertRate.mockResolvedValueOnce(0.0012);
        await handleTransaction(tempTxEvent);
      }
      const mockTxEvent = {
        filterLog: jest.fn(),
        filterFunction: jest.fn(),
        hash: "hash2",
        timestamp: 10000,
        from: spender,
        transaction: {
          data: "0x0",
        },
      };

      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([mockApprovalForAllEvent[2]]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([mockTransferBatchEvents[2]]) // ERC1155 transfers
        .mockReturnValueOnce([]); // Upgrades

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockBalanceOf.mockResolvedValue(ethers.BigNumber.from(0));

      expect(mockProvider.getCode).toHaveBeenCalledTimes(6);
      mockCalculateAlertRate.mockReturnValueOnce(0.11095).mockReturnValueOnce(0.11);

      const alertId = "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS-LOW";
      const now = new Date();
      const currentDate = now.getDate();
      const currentMonth = now.getMonth() + 1;
      const currentYear = now.getFullYear();

      const uniqueKey = ethers.utils.keccak256(
        ethers.utils.toUtf8Bytes(spender + alertId + currentDate + currentMonth + currentYear)
      );

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Account got approval for all ERC-1155 tokens",
          description: `${spender} obtained transfer approval for all ERC-1155 tokens from ${owner3}`,
          alertId: "ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL-INFO",
          severity: FindingSeverity.Info,
          type: FindingType.Info,
          metadata: {
            spender,
            owner: owner3,
            anomalyScore: "0.11095",
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
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Approval",
              confidence: 1,
            }),
          ],
        }),
        expect.objectContaining({
          name: "Previously approved assets transferred",
          description: `${spender} transferred 1 assets from 3 accounts over period of 1 days.`,
          alertId,
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            firstTxHash: "hash0",
            lastTxHash: "hash2",
            anomalyScore: "0.11",
          },
          addresses: [asset],
          labels: [
            Label.fromObject({
              entity: spender,
              entityType: EntityType.Address,
              label: "Attacker",
              confidence: 0.25,
            }),
            Label.fromObject({
              entity: "hash0",
              entityType: EntityType.Transaction,
              label: "Transfer",
              confidence: 1,
            }),
            Label.fromObject({
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Transfer",
              confidence: 1,
            }),
            Label.fromObject({
              entity: "4,0x0000000000000000000000000000000000000005",
              entityType: EntityType.Address,
              label: "NFT",
              confidence: 1,
            }),
            Label.fromObject({
              entity: "5,0x0000000000000000000000000000000000000005",
              entityType: EntityType.Address,
              label: "NFT",
              confidence: 1,
            }),
          ],
          uniqueKey,
        }),
      ]);
    });

    it("should return findings if there's a transfer following an EIP-2612's permit function call", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      const tempTxEvent = {
        filterFunction: jest
          .fn()
          .mockReturnValueOnce([mockPermitFunctionCall])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([]),
        filterLog: jest
          .fn()
          .mockReturnValueOnce([]) // ERC20 approvals
          .mockReturnValueOnce([]) // ERC721 approvals
          .mockReturnValueOnce([]) // ApprovalForAll
          .mockReturnValueOnce([]) // ERC20 transfers
          .mockReturnValueOnce([]) // ERC721 transfers
          .mockReturnValueOnce([]) // ERC1155 transfers
          .mockReturnValueOnce([]), // Upgrades
        hash: "hash33",
        timestamp: 1001,
        from: spender,
      };
      mockProvider.getCode.mockReturnValue("0x");
      mockCalculateAlertRate.mockResolvedValueOnce(0.19292);
      await handleTransaction(tempTxEvent);

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([mockTransferEvents[0]]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]) // ERC1155 transfers
        .mockReturnValueOnce([]); // Upgrades

      mockBalanceOf.mockResolvedValueOnce(ethers.BigNumber.from(0));
      mockCalculateAlertRate.mockReturnValueOnce(0.095);

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Previously permitted assets transferred",
          description: `${spender} transferred ${mockTransferEvents[0].args.value} tokens from ${owner1} to ${mockTransferEvents[0].args.to}`,
          alertId: "ICE-PHISHING-PERMITTED-ERC20-TRANSFER",
          severity: FindingSeverity.Critical,
          type: FindingType.Exploit,
          metadata: {
            owner: owner1,
            receiver: mockTransferEvents[0].args.to,
            spender: spender,
            anomalyScore: "0.095",
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
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Transfer",
              confidence: 1,
            }),
          ],
        }),
      ]);
    });

    it("should return findings if there's a transfer following a DAI-like permit function call", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      const tempTxEvent = {
        filterFunction: jest
          .fn()
          .mockReturnValueOnce([])
          .mockReturnValueOnce([mockDAILikePermitFunctionCall])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([]),
        filterLog: jest
          .fn()
          .mockReturnValueOnce([]) // ERC20 approvals
          .mockReturnValueOnce([]) // ERC721 approvals
          .mockReturnValueOnce([]) // ApprovalForAll
          .mockReturnValueOnce([]) // ERC20 transfers
          .mockReturnValueOnce([]) // ERC721 transfers
          .mockReturnValueOnce([]) // ERC1155 transfers
          .mockReturnValueOnce([]), // Upgrades
        hash: "hash33",
        timestamp: 1001,
        from: spender,
      };
      mockProvider.getCode.mockReturnValue("0x");
      mockCalculateAlertRate.mockResolvedValueOnce(0.877);
      await handleTransaction(tempTxEvent);

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([mockTransferEvents[0]]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]) // ERC1155 transfers
        .mockReturnValueOnce([]); // Upgrades

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockBalanceOf.mockResolvedValueOnce(ethers.BigNumber.from(0));
      mockCalculateAlertRate.mockReturnValueOnce(0.4111);

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Previously permitted assets transferred",
          description: `${spender} transferred ${mockTransferEvents[0].args.value} tokens from ${owner1} to ${mockTransferEvents[0].args.to}`,
          alertId: "ICE-PHISHING-PERMITTED-ERC20-TRANSFER",
          severity: FindingSeverity.Critical,
          type: FindingType.Exploit,
          metadata: {
            owner: owner1,
            receiver: mockTransferEvents[0].args.to,
            spender: spender,
            anomalyScore: "0.4111",
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
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Transfer",
              confidence: 1,
            }),
          ],
        }),
      ]);
    });

    it("should return findings if there's a transfer following a Permit2's permit function call", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      const tempTxEvent = {
        filterFunction: jest
          .fn()
          .mockReturnValueOnce([])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([mockPermit2FunctionCall])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([]),
        filterLog: jest
          .fn()
          .mockReturnValueOnce([]) // ERC20 approvals
          .mockReturnValueOnce([]) // ERC721 approvals
          .mockReturnValueOnce([]) // ApprovalForAll
          .mockReturnValueOnce([]) // ERC20 transfers
          .mockReturnValueOnce([]) // ERC721 transfers
          .mockReturnValueOnce([]) // ERC1155 transfers
          .mockReturnValueOnce([]), // Upgrades
        hash: "hash33",
        timestamp: 1001,
        from: spender,
      };
      mockProvider.getCode.mockReturnValue("0x");
      mockCalculateAlertRate.mockResolvedValueOnce(0.1877);
      await handleTransaction(tempTxEvent);

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([mockTransferEvents[0]]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]) // ERC1155 transfers
        .mockReturnValueOnce([]); // Upgrades

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockBalanceOf.mockResolvedValueOnce(ethers.BigNumber.from(0));
      mockCalculateAlertRate.mockReturnValueOnce(0.095);

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Previously permitted assets transferred",
          description: `${spender} transferred ${mockTransferEvents[0].args.value} tokens from ${owner1} to ${mockTransferEvents[0].args.to}`,
          alertId: "ICE-PHISHING-PERMITTED-ERC20-TRANSFER",
          severity: FindingSeverity.Critical,
          type: FindingType.Exploit,
          metadata: {
            owner: owner1,
            receiver: mockTransferEvents[0].args.to,
            spender: spender,
            anomalyScore: "0.095",
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
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Transfer",
              confidence: 1,
            }),
          ],
        }),
      ]);
    });

    it("should return findings if a scam address has been given permission", async () => {
      resetInit();
      resetLastBlock();
      mockProvider.getNetwork.mockReturnValueOnce({ chainId: 1 });
      const mockBlockEvent = { block: { timestamp: 1000 } };
      const axiosResponse = { data: [createAddress("0x5050")] };
      axios.get.mockResolvedValueOnce(axiosResponse);
      const date = new Date();
      const minutes = date.getMinutes();
      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        MOCK_DATABASE_OBJECTS_KEY,
        mockCounters,
        minutes // Passing minutes to make sure peristence is not triggered as minutes === lastExecutedMinute
      );
      await handleBlock(mockBlockEvent);

      const mockPermitFunctionCall = {
        address: asset,
        args: {
          owner: owner1,
          spender: createAddress("0x5050"),
          deadline: 9359543534435,
          value: ethers.BigNumber.from(210),
        },
      };

      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      mockTxEvent.filterFunction
        .mockReturnValueOnce([mockPermitFunctionCall])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockTxEvent.filterLog.mockReturnValue([]);
      mockProvider.getCode.mockReturnValue("0x");

      const axiosResponse2 = { data: { "www.scamDomain.com": [createAddress("0x5050")] } };
      axios.get.mockResolvedValueOnce(axiosResponse2);
      mockCalculateAlertRate.mockReturnValueOnce(0.004);

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Scam address, flagged in the Scam Sniffer DB, was involved in an ERC-20 permission",
          description: `${spender} gave permission to ${createAddress("0x5050")} for ${owner1}'s ERC-20 tokens`,
          alertId: "ICE-PHISHING-ERC20-SCAM-PERMIT",
          severity: FindingSeverity.High,
          type: FindingType.Suspicious,
          metadata: {
            scamAddresses: [createAddress("0x5050")],
            scamDomains: ["www.scamDomain.com"],
            msgSender: spender,
            spender: createAddress("0x5050"),
            owner: owner1,
            anomalyScore: "0.004",
          },
          addresses: [asset],
          labels: [
            Label.fromObject({
              entity: createAddress("0x5050"),
              entityType: EntityType.Address,
              label: "Attacker",
              confidence: 0.9,
            }),
            Label.fromObject({
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Permit",
              confidence: 1,
            }),
          ],
        }),
      ]);
    });

    it("should return findings if a contract deployed by a scam address has been given permission", async () => {
      resetInit();
      resetLastBlock();
      mockGetSuspiciousContracts.mockResolvedValueOnce(new Set());

      const initialize = provideInitialize(
        mockProvider,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters,
        MOCK_DATABASE_OBJECTS_KEY
      );
      for (const key in MOCK_DATABASE_KEYS) {
        mockPersistenceHelper.load.mockReturnValueOnce(mockCounters[key]);
      }
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);
      await initialize();

      const mockBlockEvent = { block: { timestamp: 1000121 } };
      const axiosResponse = { data: [createAddress("0x215050")] };
      axios.get.mockResolvedValueOnce(axiosResponse);
      const date = new Date();
      const minutes = date.getMinutes();
      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        MOCK_DATABASE_OBJECTS_KEY,
        mockCounters,
        minutes // Passing minutes to make sure peristence is not triggered as minutes === lastExecutedMinute
      );
      await handleBlock(mockBlockEvent);

      const axiosResponse3 = { data: { "www.scamDomain.com": [createAddress("0x215050")] } };
      axios.get.mockResolvedValueOnce(axiosResponse3);

      const mockPermitFunctionCall = {
        address: asset,
        args: {
          owner: owner1,
          spender: createAddress("0x23325050"),
          deadline: 9359543534435,
          value: ethers.BigNumber.from(210),
        },
      };

      mockTxEvent.filterFunction
        .mockReturnValueOnce([mockPermitFunctionCall])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockTxEvent.filterLog.mockReturnValue([]);
      mockProvider.getCode.mockReturnValueOnce("0xcccc");
      const axiosResponse1 = { data: { message: "ok", status: "1", result: [] } };
      axios.get
        .mockResolvedValueOnce(axiosResponse1)
        .mockResolvedValueOnce(axiosResponse1)
        .mockResolvedValueOnce(axiosResponse1)
        .mockResolvedValueOnce(axiosResponse1);

      const axiosResponse2 = { data: { message: "ok", result: [{ contractCreator: createAddress("0x215050") }] } };
      axios.get.mockResolvedValueOnce(axiosResponse2);
      mockCalculateAlertRate.mockReturnValueOnce(0.4).mockReturnValueOnce(0.3);
      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Contract created by a scam address (flagged in the Scam Sniffer DB) was involved in an ERC-20 permission",
          description: `${spender} gave permission to ${createAddress("0x23325050")} for ${owner1}'s ERC-20 tokens`,
          alertId: "ICE-PHISHING-ERC20-SCAM-CREATOR-PERMIT",
          severity: FindingSeverity.High,
          type: FindingType.Suspicious,
          metadata: {
            scamAddress: createAddress("0x215050"),
            scamDomains: ["www.scamDomain.com"],
            msgSender: spender,
            spender: createAddress("0x23325050"),
            owner: owner1,
            anomalyScore: "0.4",
          },
          addresses: [asset],
          labels: [
            Label.fromObject({
              entity: createAddress("0x23325050"),
              entityType: EntityType.Address,
              label: "Attacker",
              confidence: 0.9,
            }),
            Label.fromObject({
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Permit",
              confidence: 1,
            }),
          ],
        }),
        expect.objectContaining({
          name: "Account got permission for ERC-20 tokens",
          description: `${spender} gave permission to ${createAddress("0x23325050")} for ${owner1}'s ERC-20 tokens`,
          alertId: "ICE-PHISHING-ERC20-PERMIT-INFO",
          severity: FindingSeverity.Info,
          type: FindingType.Info,
          metadata: {
            msgSender: spender,
            spender: createAddress("0x23325050"),
            owner: owner1,
            anomalyScore: "0.3",
          },
          addresses: [asset],
          labels: [
            Label.fromObject({
              entity: createAddress("0x23325050"),
              entityType: EntityType.Address,
              label: "Attacker",
              confidence: 0.2,
            }),
            Label.fromObject({
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Permit",
              confidence: 1,
            }),
          ],
        }),
      ]);
    });

    it("should return findings if a scam address has been approved", async () => {
      resetInit();
      resetLastBlock();

      const mockBlockEvent = { block: { timestamp: 1000 } };
      const axiosResponse = { data: [spender] };
      axios.get.mockResolvedValueOnce(axiosResponse);
      const date = new Date();
      const minutes = date.getMinutes();
      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        MOCK_DATABASE_OBJECTS_KEY,
        mockCounters,
        minutes // Passing minutes to make sure peristence is not triggered as minutes === lastExecutedMinute
      );
      await handleBlock(mockBlockEvent);

      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      const mockTxEvent = {
        filterLog: jest.fn(),
        filterFunction: jest.fn(),
        hash: "hash2",
        timestamp: 10000,
        from: spender,
        blockNumber: 123,
      };

      mockTxEvent.filterLog
        .mockReturnValueOnce([mockApprovalERC20Events[0]]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]) // ERC1155 transfers
        .mockReturnValueOnce([]); // Upgrades

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);

      const axiosResponse2 = { data: { "www.scamDomain.com": [spender] } };
      axios.get.mockResolvedValueOnce(axiosResponse2);
      mockProvider.getCode.mockReturnValue("0x");
      mockCalculateAlertRate.mockReturnValueOnce(0.003);

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Scam address, flagged in the Scam Sniffer DB, got approval to spend assets",
          description: `Scam address ${spender} got approval for ${owner1}'s assets`,
          alertId: "ICE-PHISHING-SCAM-APPROVAL",
          severity: FindingSeverity.High,
          type: FindingType.Suspicious,
          metadata: {
            scamDomains: ["www.scamDomain.com"],
            scamSpender: spender,
            owner: owner1,
            anomalyScore: "0.003",
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
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Approval",
              confidence: 1,
            }),
          ],
        }),
      ]);
    });

    it("should return findings if a scam address is involved in a transfer", async () => {
      resetInit();

      const mockBlockEvent = { block: { timestamp: 1000 } };
      const axiosResponse = { data: [spender] };
      axios.get.mockResolvedValueOnce(axiosResponse);
      const date = new Date();
      const minutes = date.getMinutes();
      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        MOCK_DATABASE_OBJECTS_KEY,
        mockCounters,
        minutes // Passing minutes to make sure peristence is not triggered as minutes === lastExecutedMinute
      );
      mockGetSuspiciousContracts.mockResolvedValueOnce(
        new Set([{ address: createAddress("0xabcdabcd"), creator: createAddress("0xeeffeeff") }])
      );
      await handleBlock(mockBlockEvent);

      const axiosResponse2 = { data: { "www.scamDomain.com": [spender] } };
      axios.get.mockResolvedValueOnce(axiosResponse2);

      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([mockTransferEvents[0]]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]) // ERC1155 transfers
        .mockReturnValueOnce([]); // Upgrades

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockProvider.getCode.mockReturnValue("0x");
      mockCalculateAlertRate.mockReturnValueOnce(0.9);

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Scam address, flagged in the Scam Sniffer DB, was involved in an asset transfer",
          description: `${spender} transferred assets from ${owner1} to ${mockTransferEvents[0].args.to}`,
          alertId: "ICE-PHISHING-SCAM-TRANSFER",
          severity: FindingSeverity.Critical,
          type: FindingType.Exploit,
          metadata: {
            scamAddresses: [spender],
            scamDomains: ["www.scamDomain.com"],
            msgSender: spender,
            owner: owner1,
            receiver: mockTransferEvents[0].args.to,
            anomalyScore: "0.9",
          },
          addresses: [asset],
          labels: [
            Label.fromObject({
              entity: spender,
              entityType: EntityType.Address,
              label: "Attacker",
              confidence: 0.95,
            }),
            Label.fromObject({
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Transfer",
              confidence: 1,
            }),
          ],
        }),
      ]);
    });

    it("should return findings if a suspicious contract is involved in a transfer", async () => {
      resetInit();

      const initialize = provideInitialize(
        mockProvider,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters,
        MOCK_DATABASE_OBJECTS_KEY
      );
      for (const key in MOCK_DATABASE_KEYS) {
        mockPersistenceHelper.load.mockReturnValueOnce(mockCounters[key]);
      }
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      await initialize();

      const suspiciousReceiver = createChecksumAddress("0xabcdabcd");
      const suspiciousContractCreator = createChecksumAddress("0xfefefe");

      const date = new Date();
      const minutes = date.getMinutes();
      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        MOCK_DATABASE_OBJECTS_KEY,
        mockCounters,
        minutes // Passing minutes to make sure peristence is not triggered as minutes === lastExecutedMinute
      );

      mockGetSuspiciousContracts.mockResolvedValueOnce(
        new Set([{ address: suspiciousReceiver, creator: suspiciousContractCreator }])
      );

      const mockBlockEvent = { block: { timestamp: 1000 } };

      const axiosResponse = { data: [] };
      axios.get.mockResolvedValueOnce(axiosResponse);

      await handleBlock(mockBlockEvent);

      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      const mockTxEvent = {
        filterLog: jest.fn(),
        filterFunction: jest.fn(),
        hash: "hash2",
        timestamp: 10000,
        from: createAddress("0x12331"),
        transaction: {
          data: "0x",
        },
      };
      const mockTransferEvent = {
        address: asset,
        name: "Transfer",
        args: {
          from: owner1,
          to: suspiciousReceiver,
          value: ethers.BigNumber.from(210),
        },
      };

      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([mockTransferEvent]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]) // ERC1155 transfers
        .mockReturnValueOnce([]); // Upgrades

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockProvider.getCode.mockReturnValue("0x333");

      const axiosResponse2 = {
        data: { message: "okkk", status: "1", result: [{ contractCreator: createAddress("0xaaaabbb") }] },
      };
      axios.get.mockResolvedValue(axiosResponse2);
      mockCalculateAlertRate.mockReturnValueOnce(0.5);

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Suspicious contract (creator) was involved in an asset transfer",
          description: `${createAddress("0x12331")} transferred assets from ${owner1} to ${suspiciousReceiver}`,
          alertId: "ICE-PHISHING-SUSPICIOUS-TRANSFER",
          severity: FindingSeverity.High,
          type: FindingType.Suspicious,
          metadata: {
            msgSender: createAddress("0x12331"),
            owner: owner1,
            receiver: suspiciousReceiver,
            suspiciousContract: suspiciousReceiver,
            suspiciousContractCreator,
            anomalyScore: "0.5",
          },
          addresses: [asset],
          labels: [
            Label.fromObject({
              entity: suspiciousReceiver,
              entityType: EntityType.Address,
              label: "Attacker",
              confidence: 0.6,
            }),
            Label.fromObject({
              entity: suspiciousContractCreator,
              entityType: EntityType.Address,
              label: "Attacker",
              confidence: 0.6,
            }),
            Label.fromObject({
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Transfer",
              confidence: 1,
            }),
          ],
        }),
      ]);
    });

    it("should return findings if a creator of a suspicious contract is involved in a transfer", async () => {
      resetInit();
      const initialize = provideInitialize(
        mockProvider,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters,
        MOCK_DATABASE_OBJECTS_KEY
      );
      for (const key in MOCK_DATABASE_KEYS) {
        mockPersistenceHelper.load.mockReturnValueOnce(mockCounters[key]);
      }
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      await initialize();
      const suspiciousContract = createChecksumAddress("0xabcdabcd");
      const suspiciousContractCreator = createChecksumAddress("0xfefefe");
      const date = new Date();
      const minutes = date.getMinutes();
      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        MOCK_DATABASE_OBJECTS_KEY,
        mockCounters,
        minutes // Passing minutes to make sure peristence is not triggered as minutes === lastExecutedMinute
      );
      mockGetSuspiciousContracts.mockResolvedValueOnce(
        new Set([{ address: suspiciousContract, creator: suspiciousContractCreator }])
      );
      const mockBlockEvent = { block: { timestamp: 1000 } };
      const axiosResponse = { data: [] };
      axios.get.mockResolvedValueOnce(axiosResponse);
      await handleBlock(mockBlockEvent);

      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      const mockTxEvent = {
        filterLog: jest.fn(),
        filterFunction: jest.fn(),
        hash: "hash2",
        timestamp: 10000,
        from: createAddress("0x12331"),
        transaction: {
          data: "0x",
        },
      };
      const mockTransferEvent = {
        address: asset,
        name: "Transfer",
        args: {
          from: owner1,
          to: suspiciousContractCreator,
          value: ethers.BigNumber.from(210),
        },
      };

      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([mockTransferEvent]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]) // ERC1155 transfers
        .mockReturnValueOnce([]); // Upgrades

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockProvider.getCode.mockReturnValue("0x333");

      const axiosResponse2 = {
        data: { message: "okkk", status: "1", result: [{ contractCreator: createAddress("0xaaaabbb") }] },
      };
      axios.get.mockResolvedValue(axiosResponse2);
      mockCalculateAlertRate.mockReturnValueOnce(0.665);
      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Suspicious contract (creator) was involved in an asset transfer",
          description: `${createAddress("0x12331")} transferred assets from ${owner1} to ${suspiciousContractCreator}`,
          alertId: "ICE-PHISHING-SUSPICIOUS-TRANSFER",
          severity: FindingSeverity.High,
          type: FindingType.Suspicious,
          metadata: {
            msgSender: createAddress("0x12331"),
            owner: owner1,
            receiver: suspiciousContractCreator,
            suspiciousContract,
            suspiciousContractCreator,
            anomalyScore: "0.665",
          },
          addresses: [asset],
          labels: [
            Label.fromObject({
              entity: suspiciousContract,
              entityType: EntityType.Address,
              label: "Attacker",
              confidence: 0.6,
            }),
            Label.fromObject({
              entity: suspiciousContractCreator,
              entityType: EntityType.Address,
              label: "Attacker",
              confidence: 0.6,
            }),
            Label.fromObject({
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Transfer",
              confidence: 1,
            }),
          ],
        }),
      ]);
    });

    it("should return findings if a creator of a suspicious contract gets approval", async () => {
      resetInit();

      const mockBlockEvent = { block: { timestamp: 104353 } };
      const axiosResponse = { data: [createAddress("0x23232")] };
      axios.get.mockResolvedValueOnce(axiosResponse);

      const date = new Date();
      const minutes = date.getMinutes();
      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        MOCK_DATABASE_OBJECTS_KEY,
        mockCounters,
        minutes // Passing minutes to make sure peristence is not triggered as minutes === lastExecutedMinute
      );
      mockGetSuspiciousContracts.mockResolvedValueOnce(
        new Set([{ address: createAddress("0xabcdabcd"), creator: createAddress("0x01") }])
      );
      await handleBlock(mockBlockEvent);

      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      mockTxEvent.filterLog
        .mockReturnValueOnce([mockApprovalERC20Events[0]]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]) // ERC1155 transfers
        .mockReturnValueOnce([]); // Upgrades

      mockTxEvent.filterFunction
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([])
        .mockReturnValueOnce([]);
      mockProvider.getCode.mockReturnValue("0x");
      mockCalculateAlertRate.mockReturnValueOnce(0.6);
      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Suspicious contract (creator) got approval to spend assets",
          description: `Suspicious address ${spender} got approval for ${owner1}'s assets`,
          alertId: "ICE-PHISHING-SUSPICIOUS-APPROVAL",
          severity: FindingSeverity.Medium,
          type: FindingType.Suspicious,
          metadata: {
            suspiciousContract: createAddress("0xabcdabcd"),
            suspiciousContractCreator: spender,
            owner: owner1,
            suspiciousSpender: spender,
            anomalyScore: "0.6",
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
              entity: "hash2",
              entityType: EntityType.Transaction,
              label: "Approval",
              confidence: 1,
            }),
          ],
        }),
      ]);
    });

    it("should return findings if a victim was tricked into sending funds through the 'pull and sweepToken' technique", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);
      const victim = createAddress("0x12331");
      const mockTxEvent = {
        filterFunction: jest
          .fn()
          .mockReturnValueOnce([])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([mockPullFunctionCall])
          .mockReturnValueOnce([mockSweepTokenFunctionCall]),
        filterLog: jest
          .fn()
          .mockReturnValueOnce([]) // ERC20 approvals
          .mockReturnValueOnce([]) // ERC721 approvals
          .mockReturnValueOnce([]) // ApprovalForAll
          .mockReturnValueOnce([]) // ERC20 transfers
          .mockReturnValueOnce([]) // ERC721 transfers
          .mockReturnValueOnce([]) // ERC1155 transfers
          .mockReturnValueOnce([]), // Upgrades
        hash: "hash33",
        timestamp: 1001,
        from: victim,
      };
      mockCalculateAlertRate.mockReturnValueOnce(0.9);

      const findings = await handleTransaction(mockTxEvent);
      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Attacker stole funds through Router V3's pull and sweepTokens functions",
          description: `${mockRecipient} received ${ethers.BigNumber.from(210)} tokens (${asset}) from ${victim}`,
          alertId: "ICE-PHISHING-PULL-SWEEPTOKEN",
          severity: FindingSeverity.Critical,
          type: FindingType.Suspicious,
          metadata: {
            attacker: mockRecipient,
            victim,
            anomalyScore: "0.9",
          },
          addresses: asset,
          labels: [
            Label.fromObject({
              entity: mockRecipient,
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
              entity: "hash33",
              entityType: EntityType.Transaction,
              label: "Attack",
              confidence: 0.8,
            }),
          ],
        }),
      ]);
    });

    it("should return findings if a victim was tricked into upgrading their Opensea proxy to an attacker's implementation contract", async () => {
      const initialize = provideInitialize(
        mockProvider,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters,
        MOCK_DATABASE_OBJECTS_KEY
      );
      for (const key in MOCK_DATABASE_KEYS) {
        mockPersistenceHelper.load.mockReturnValueOnce(mockCounters[key]);
      }
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      await initialize();

      const victim = createAddress("0x12331");
      const mockTxEvent = {
        filterFunction: jest
          .fn()
          .mockReturnValueOnce([])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([]),
        filterLog: jest
          .fn()
          .mockReturnValueOnce([]) // ERC20 approvals
          .mockReturnValueOnce([]) // ERC721 approvals
          .mockReturnValueOnce([]) // ApprovalForAll
          .mockReturnValueOnce([]) // ERC20 transfers
          .mockReturnValueOnce([]) // ERC721 transfers
          .mockReturnValueOnce([]) // ERC1155 transfers
          .mockReturnValueOnce([mockUpgradedEvents[0]]), // Upgrades
        hash: "hash33",
        timestamp: 1001,
        from: victim,
        logs: [{}], //txEvent.logs.length === 1
      };
      const axiosResponse1 = {
        data: {
          message: "ok",
          status: "1",
          result: [
            {
              address: "0x1abc86032b4dadfa3adf93f92caf294ecd24b42d",
              topics: [
                "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b",
                "0x000000000000000000000000f9e266af4bca5890e2781812cc6a6e89495a79f2",
              ],
              data: "0x",
              blockNumber: "0xd75d75",
              blockHash: "0x0c30053171da0b040cb4d9da49511d18c53022e015c813a173eacd7e726d43f2",
              timeStamp: "0x61f7f18c",
              gasPrice: "0x1ec7e54be4",
              gasUsed: "0x61122",
              logIndex: "0x61",
              transactionHash: "0x61b2ff92ff7edb481daabed070486a740073b52875e1df92696eb254abbda63c",
              transactionIndex: "0x5e",
            },
          ],
        },
      };
      const axiosResponse2 = {
        data: { message: "totally ok", status: "1", result: [{ contractCreator: createAddress("0xbbbb") }] },
      };
      axios.get
        .mockResolvedValueOnce({}) // Scamsniffer DB
        .mockResolvedValueOnce(axiosResponse1) // Etherscan Past Events
        .mockResolvedValueOnce(axiosResponse2); // Etherscan Contract Creator
      mockCalculateAlertRate.mockReturnValueOnce(0.239);

      const findings = await handleTransaction(mockTxEvent);
      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Opensea proxy implementation changed to attacker's contract",
          description: `${victim} was tricked into upgrading their Opensea proxy implementation to ${mockImplementation} created by ${createAddress(
            "0xbbbb"
          )}`,
          alertId: "ICE-PHISHING-OPENSEA-PROXY-UPGRADE",
          severity: FindingSeverity.Critical,
          type: FindingType.Suspicious,
          metadata: {
            attacker: createAddress("0xbbbb"),
            victim,
            newImplementation: mockImplementation,
            anomalyScore: "0.239",
          },
          labels: [
            Label.fromObject({
              entity: createAddress("0xbbbb"),
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
              entity: "hash33",
              entityType: EntityType.Transaction,
              label: "Attack",
              confidence: 0.8,
            }),
          ],
        }),
      ]);
    });

    it("should return findings when there's a possible pig butchering attack", async () => {
      const USDT = STABLECOINS[0];
      const mockTransferEvents = [
        {
          address: USDT,
          name: "Transfer",
          args: {
            from: owner1,
            to: createAddress("0x11"),
            value: ethers.BigNumber.from(210),
          },
        },

        {
          address: USDT,
          name: "Transfer",
          args: {
            from: owner3,
            to: createAddress("0x11"),
            value: ethers.BigNumber.from(11210),
          },
        },
      ];

      const attacker = createAddress("0x812331");

      const mockTxEvent = {
        filterFunction: jest
          .fn()
          .mockReturnValueOnce([])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([]),
        filterLog: jest
          .fn()
          .mockReturnValueOnce([]) // ERC20 approvals
          .mockReturnValueOnce([]) // ERC721 approvals
          .mockReturnValueOnce([]) // ApprovalForAll
          .mockReturnValueOnce([mockTransferEvents[0]]) // ERC20 transfers
          .mockReturnValueOnce([]) // ERC721 transfers
          .mockReturnValueOnce([]) // ERC1155 transfers
          .mockReturnValueOnce([]), // Upgrades
        hash: "hash33",
        timestamp: 1001,
        blockNumber: 213124,
        from: attacker,
        transaction: {
          data: "0x23b872dd",
        },
      };

      for (const key in MOCK_DATABASE_KEYS) {
        mockPersistenceHelper.load.mockReturnValueOnce(mockCounters[key]);
      }
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      await initialize();
      const axiosResponse = {
        data: { message: "okkk", status: "1", result: [] },
      };
      axios.get.mockResolvedValue(axiosResponse);
      mockProvider.getCode.mockReturnValue("0x");
      mockBalanceOf.mockResolvedValue(ethers.BigNumber.from(0));
      mockProvider.getTransactionCount.mockReturnValue(1);
      const axiosResponse2 = {
        data: { message: "okkk", status: "1", result: [{ from: CEX_ADDRESSES[0], functionName: "" }] },
      };
      axios.get.mockResolvedValue(axiosResponse2);
      await handleTransaction(mockTxEvent);

      const axiosResponse1b = {
        data: { message: "okkk", status: "1", result: [] },
      };
      axios.get.mockResolvedValue(axiosResponse1b);
      mockProvider.getCode.mockReturnValue("0x");
      mockBalanceOf.mockResolvedValue(ethers.BigNumber.from(0));
      mockProvider.getTransactionCount.mockReturnValue(1);
      const axiosResponse2b = {
        data: { message: "okkk", status: "1", result: [{ from: CEX_ADDRESSES[0], functionName: "" }] },
      };
      axios.get.mockResolvedValue(axiosResponse2b);

      const mockTxEvent1 = {
        filterFunction: jest
          .fn()
          .mockReturnValueOnce([])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([]),
        filterLog: jest
          .fn()
          .mockReturnValueOnce([]) // ERC20 approvals
          .mockReturnValueOnce([]) // ERC721 approvals
          .mockReturnValueOnce([]) // ApprovalForAll
          .mockReturnValueOnce([mockTransferEvents[1]]) // ERC20 transfers
          .mockReturnValueOnce([]) // ERC721 transfers
          .mockReturnValueOnce([]) // ERC1155 transfers
          .mockReturnValueOnce([]), // Upgrades
        hash: "hash334",
        timestamp: 1101,
        blockNumber: 213125,
        from: attacker,
        transaction: {
          data: "0x23b872dd",
        },
      };

      mockCalculateAlertRate.mockReturnValueOnce("0.3");

      const alertId = "ICE-PHISHING-PIG-BUTCHERING";
      const now = new Date();
      const currentDate = now.getDate();
      const currentMonth = now.getMonth() + 1;
      const currentYear = now.getFullYear();

      const uniqueKey = ethers.utils.keccak256(
        ethers.utils.toUtf8Bytes(
          createAddress("0x11") + mockTxEvent1.hash + alertId + currentDate + currentMonth + currentYear
        )
      );

      const findings = await handleTransaction(mockTxEvent1);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Possible Pig Butchering Attack",
          description: `${createAddress("0x11")} received funds through a pig butchering attack`,
          alertId,
          severity: FindingSeverity.Critical,
          type: FindingType.Suspicious,
          metadata: {
            anomalyScore: "0.3",
            receiver: createAddress("0x11"),
            initiator1: attacker,
            victim1: owner1,
            victim2: owner3,
          },
          labels: [
            Label.fromObject({
              entity: "hash334",
              entityType: EntityType.Transaction,
              label: "Attack",
              confidence: 0.7,
            }),
            Label.fromObject({
              entity: createAddress("0x11"),
              entityType: EntityType.Address,
              label: "Attacker",
              confidence: 0.7,
            }),
            Label.fromObject({
              entity: attacker,
              entityType: EntityType.Address,
              label: "Attacker",
              confidence: 0.7,
            }),
            Label.fromObject({
              entity: owner1,
              entityType: EntityType.Address,
              label: "Victim",
              confidence: 0.7,
            }),
            Label.fromObject({
              entity: owner3,
              entityType: EntityType.Address,
              label: "Victim",
              confidence: 0.7,
            }),
          ],
          uniqueKey,
        }),
      ]);
    });

    it("should return findings when an approval is granted to a 0-nonce EOA", async () => {
      mockProvider.getNetwork.mockReturnValue({ chainId: 1 });
      await initialize();

      const victim = createAddress("0x2211");

      const mockTxEvent = {
        filterFunction: jest
          .fn()
          .mockReturnValueOnce([])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([])
          .mockReturnValueOnce([]),
        filterLog: jest
          .fn()
          .mockReturnValueOnce([mockApprovalERC20Events[3]]) // ERC20 approvals
          .mockReturnValueOnce([]) // ERC721 approvals
          .mockReturnValueOnce([]) // ApprovalForAll
          .mockReturnValueOnce([]) // ERC20 transfers
          .mockReturnValueOnce([]) // ERC721 transfers
          .mockReturnValueOnce([]) // ERC1155 transfers
          .mockReturnValueOnce([]), // Upgrades
        hash: `hash123`,
        timestamp: 4000,
        from: victim,
      };
      mockProvider.getCode.mockReturnValue("0x");
      mockProvider.getTransactionCount.mockReturnValueOnce(1230).mockResolvedValueOnce(0);

      const axiosResponse = {
        data: { message: "No transactions found", status: "0", result: [] },
      };
      axios.get.mockResolvedValue(axiosResponse);

      const alertId = "ICE-PHISHING-ZERO-NONCE-ALLOWANCE";
      mockCalculateAlertRate.mockReturnValueOnce("0.08910234");

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        expect.objectContaining({
          name: "Approval/Permission has been given to a 0 nonce address",
          description: `${spenderNewEOA} received allowance from ${victim} to spend (${asset}) tokens`,
          alertId: alertId,
          severity: FindingSeverity.High,
          type: FindingType.Suspicious,
          metadata: {
            attacker: spenderNewEOA,
            victim,
            anomalyScore: "0.08910234",
          },
          addresses: [asset],
          labels: [
            Label.fromObject({
              entity: spenderNewEOA,
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
              entity: "hash123",
              entityType: EntityType.Transaction,
              label: "Attack",
              confidence: 0.7,
            }),
          ],
        }),
      ]);
    });
  });

  describe("handleBlock", () => {
    const timePeriod = 2 * timePeriodDays * 24 * 60 * 60;

    beforeEach(() => {
      resetLastTimestamp();
      resetInit();
      Object.keys(mockObjects).forEach((s) => {
        mockObjects[s] = {};
      });
    });

    beforeEach(async () => {
      mockPersistenceHelper.persist.mockClear();
    });

    it("should do nothing if enough time has not passed", async () => {
      const date = new Date();
      const minutes = date.getMinutes();
      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        MOCK_DATABASE_OBJECTS_KEY,
        mockCounters,
        minutes // Passing minutes to make sure peristence is not triggered as minutes === lastExecutedMinute
      );
      const axiosResponse = { data: [createAddress("0x5050")] };
      axios.get.mockResolvedValue(axiosResponse);
      const mockBlockEvent = { block: { timestamp: 1000, number: 123 } };
      mockGetSuspiciousContracts.mockResolvedValueOnce({});

      mockObjects.approvals[spender] = [{ timestamp: 1000 }];
      mockObjects.approvalsERC20[spender] = [{ timestamp: 1000 }];
      mockObjects.approvalsERC721[spender] = [{ timestamp: 1000 }];
      mockObjects.approvalsForAll721[spender] = [{ timestamp: 1000 }];
      mockObjects.approvalsForAll1155[spender] = [{ timestamp: 1000 }];
      mockObjects.permissions[spender] = [{ deadline: 10 }];
      mockObjects.transfers[spender] = [{ timestamp: 1000 }];
      mockObjects.approvalsInfoSeverity[spender] = [{ timestamp: 1000 }];
      mockObjects.approvalsERC20InfoSeverity[spender] = [{ timestamp: 1000 }];
      mockObjects.approvalsERC721InfoSeverity[spender] = [{ timestamp: 1000 }];
      mockObjects.approvalsForAll721InfoSeverity[spender] = [{ timestamp: 1000 }];
      mockObjects.approvalsForAll1155InfoSeverity[spender] = [{ timestamp: 1000 }];
      mockObjects.permissionsInfoSeverity[spender] = [{ deadline: 10 }];
      mockObjects.transfersLowSeverity[spender] = [{ timestamp: 1000 }];
      mockObjects.pigButcheringTransfers[spender] = [{ timestamp: 1000 }];
      await handleBlock(mockBlockEvent);

      expect(Object.keys(mockObjects.approvals).length).toStrictEqual(1);
      expect(Object.keys(mockObjects.approvalsERC20).length).toStrictEqual(1);
      expect(Object.keys(mockObjects.approvalsERC721).length).toStrictEqual(1);
      expect(Object.keys(mockObjects.approvalsForAll721).length).toStrictEqual(1);
      expect(Object.keys(mockObjects.approvalsForAll1155).length).toStrictEqual(1);
      expect(Object.keys(mockObjects.permissions).length).toStrictEqual(1);
      expect(Object.keys(mockObjects.transfers).length).toStrictEqual(1);
      expect(Object.keys(mockObjects.approvalsInfoSeverity).length).toStrictEqual(1);
      expect(Object.keys(mockObjects.approvalsERC20InfoSeverity).length).toStrictEqual(1);
      expect(Object.keys(mockObjects.approvalsERC721InfoSeverity).length).toStrictEqual(1);
      expect(Object.keys(mockObjects.approvalsForAll721InfoSeverity).length).toStrictEqual(1);
      expect(Object.keys(mockObjects.approvalsForAll1155InfoSeverity).length).toStrictEqual(1);
      expect(Object.keys(mockObjects.permissionsInfoSeverity).length).toStrictEqual(1);
      expect(Object.keys(mockObjects.transfersLowSeverity).length).toStrictEqual(1);
      expect(Object.keys(mockObjects.pigButcheringTransfers).length).toStrictEqual(1);
    });

    it("should not delete the entry if it was updated recently/permission deadline has not passed", async () => {
      const initialize = provideInitialize(
        mockProvider,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters,
        MOCK_DATABASE_OBJECTS_KEY
      );
      mockProvider.getNetwork.mockReturnValue({ chainId: 1 });

      for (const key in MOCK_DATABASE_KEYS) {
        mockPersistenceHelper.load.mockReturnValueOnce(mockCounters[key]);
      }
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);
      await initialize();

      const date = new Date();
      const minutes = date.getMinutes();
      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        MOCK_DATABASE_OBJECTS_KEY,
        mockCounters,
        minutes // Passing minutes to make sure peristence is not triggered as minutes === lastExecutedMinute
      );

      const axiosResponse = { data: [createAddress("0x5050")] };
      axios.get.mockResolvedValue(axiosResponse);
      const mockBlockEvent = { block: { timestamp: timePeriod, number: 127 } };
      mockGetSuspiciousContracts.mockResolvedValueOnce({});
      mockObjects.approvals[spender] = [{ timestamp: timePeriod }];
      mockObjects.approvalsERC20[spender] = [{ timestamp: timePeriod }];
      mockObjects.approvalsERC721[spender] = [{ timestamp: timePeriod }];
      mockObjects.approvalsForAll721[spender] = [{ timestamp: timePeriod }];
      mockObjects.approvalsForAll1155[spender] = [{ timestamp: timePeriod }];
      mockObjects.permissions[spender] = [{ deadline: 5184001 }];
      mockObjects.transfers[spender] = [{ timestamp: timePeriod }];

      await handleBlock(mockBlockEvent);

      expect(Object.keys(mockObjects.approvals).length).toStrictEqual(1);
      expect(Object.keys(mockObjects.approvalsERC20).length).toStrictEqual(1);
      expect(Object.keys(mockObjects.approvalsERC721).length).toStrictEqual(1);
      expect(Object.keys(mockObjects.approvalsForAll721).length).toStrictEqual(1);
      expect(Object.keys(mockObjects.approvalsForAll1155).length).toStrictEqual(1);
      expect(Object.keys(mockObjects.permissions).length).toStrictEqual(1);
      expect(Object.keys(mockObjects.transfers).length).toStrictEqual(1);
    });

    it("should delete the entry if it was not updated recently/permission deadline has expired", async () => {
      const initialize = provideInitialize(
        mockProvider,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters,
        MOCK_DATABASE_OBJECTS_KEY
      );
      mockProvider.getNetwork.mockReturnValue({ chainId: 1 });

      for (const key in MOCK_DATABASE_KEYS) {
        mockPersistenceHelper.load.mockReturnValueOnce(mockCounters[key]);
      }
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);
      await initialize();

      const date = new Date();
      const minutes = date.getMinutes();
      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        MOCK_DATABASE_OBJECTS_KEY,
        mockCounters,
        minutes // Passing minutes to make sure peristence is not triggered as minutes === lastExecutedMinute
      );

      const axiosResponse = { data: [createAddress("0x5050")] };
      axios.get.mockResolvedValue(axiosResponse);
      const mockBlockEvent = { block: { timestamp: timePeriod } };
      mockGetSuspiciousContracts.mockResolvedValueOnce({});

      mockObjects.approvals[spender] = [{ timestamp: 1000 }];
      mockObjects.approvalsERC20[spender] = [{ timestamp: 1000 }];
      mockObjects.approvalsERC721[spender] = [{ timestamp: 1000 }];
      mockObjects.approvalsForAll721[spender] = [{ timestamp: 1000 }];
      mockObjects.approvalsForAll1155[spender] = [{ timestamp: 1000 }];
      mockObjects.permissions[spender] = [{ deadline: 1000 }];
      mockObjects.transfers[spender] = [{ timestamp: 1000 }];
      mockObjects.pigButcheringTransfers[spender] = [{ timestamp: 1000 }];

      await handleBlock(mockBlockEvent);

      expect(Object.keys(mockObjects.approvals).length).toStrictEqual(0);
      expect(Object.keys(mockObjects.approvalsERC20).length).toStrictEqual(0);
      expect(Object.keys(mockObjects.approvalsERC721).length).toStrictEqual(0);
      expect(Object.keys(mockObjects.approvalsForAll721).length).toStrictEqual(0);
      expect(Object.keys(mockObjects.approvalsForAll1155).length).toStrictEqual(0);
      expect(Object.keys(mockObjects.permissions).length).toStrictEqual(0);
      expect(Object.keys(mockObjects.transfers).length).toStrictEqual(0);
      expect(Object.keys(mockObjects.pigButcheringTransfers).length).toStrictEqual(0);
    });

    it("should populate the suspicious contracts set correctly", async () => {
      const date = new Date();
      const minutes = date.getMinutes();
      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        MOCK_DATABASE_OBJECTS_KEY,
        mockCounters,
        minutes // Passing minutes to make sure peristence is not triggered as minutes === lastExecutedMinute
      );

      const axiosResponse = { data: [createAddress("0x5050")] };
      axios.get.mockResolvedValue(axiosResponse);
      const mockBlockEvent = { block: { number: 239 } };
      mockGetSuspiciousContracts.mockResolvedValueOnce(new Set([createAddress("0x34234324")]));
      await handleBlock(mockBlockEvent);
      expect(getSuspiciousContracts().size).toStrictEqual(1);

      const mockBlockEvent2 = { block: { number: 240 } };
      mockGetSuspiciousContracts.mockResolvedValueOnce(new Set([createAddress("0x765756756")]));
      await handleBlock(mockBlockEvent2);
      expect(getSuspiciousContracts().size).toStrictEqual(2);
    });

    it("should persist the value in a block evenly divisible by 240", async () => {
      const axiosResponse = { data: [createAddress("0x5050")] };
      axios.get.mockResolvedValue(axiosResponse);

      const date = new Date();
      const minutes = date.getMinutes();
      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        MOCK_DATABASE_OBJECTS_KEY,
        mockCounters,
        minutes // Passing minutes to make sure peristence is not triggered as minutes === lastExecutedMinute
      );

      const mockBlockEvent1 = {
        block: {
          number: 719,
        },
      };
      const mockBlockEvent2 = {
        block: {
          number: 720,
        },
      };

      mockGetSuspiciousContracts.mockResolvedValueOnce(new Set([createAddress("0x34234324")]));
      await handleBlock(mockBlockEvent1);

      mockGetSuspiciousContracts.mockResolvedValueOnce(new Set([createAddress("0x34234324")]));
      await handleBlock(mockBlockEvent2);

      expect(mockPersistenceHelper.persist).toHaveBeenCalledTimes(8);
    });

    it("should not persist values because block is not evenly divisible by 240", async () => {
      const axiosResponse = { data: [createAddress("0x5050")] };
      axios.get.mockResolvedValue(axiosResponse);

      const date = new Date();
      const minutes = date.getMinutes();
      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        MOCK_DATABASE_OBJECTS_KEY,
        mockCounters,
        minutes // Passing minutes to make sure peristence is not triggered as minutes === lastExecutedMinute
      );

      const mockBlockEvent = {
        block: {
          number: 600,
        },
      };

      await handleBlock(mockBlockEvent);

      expect(mockPersistenceHelper.persist).toHaveBeenCalledTimes(0);
    });
  });
});

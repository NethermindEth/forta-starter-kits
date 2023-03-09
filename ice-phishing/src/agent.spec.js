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
} = require("./agent");

const approveCountThreshold = 2;
const approveForAllCountThreshold = 2;
const transferCountThreshold = 2;
const timePeriodDays = 30;
const nonceThreshold = 100;
const maxAddressAlertsPerPeriod = 3;
const verifiedContractTxsThreshold = 1;

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
};

const spender = createAddress("0x01");
const owner1 = createAddress("0x02");
const owner2 = createAddress("0x03");
const owner3 = createAddress("0x04");
const asset = createAddress("0x05");
const asset2 = createAddress("0x06");

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
    maxAddressAlertsPerPeriod,
  }),
  { virtual: true }
);

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
    expiry: 8359543534435,
  },
};

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

const MOCK_DATABASE_OBJECTS_KEYS = {
  approvals: "nm-icephishing-bot-approvals-key-shard",
  approvalsERC20: "nm-icephishing-bot-approvals-erc20-key-shard",
  approvalsERC721: "nm-icephishing-bot-approvals-erc721-key-shard",
  approvalsForAll721: "nm-icephishing-bot-approvals-for-all-721-key-shard",
  approvalsForAll1155: "nm-icephishing-bot-approvals-for-all-1155-key-shard",
  approvalsInfoSeverity: "nm-icephishing-bot-approvals-info-severity-key-shard",
  approvalsERC20InfoSeverity: "nm-icephishing-bot-approvals-erc20-info-severity-key-shard",
  approvalsERC721InfoSeverity: "nm-icephishing-bot-approvals-erc721-info-severity-key-shard",
  approvalsForAll721InfoSeverity: "nm-icephishing-bot-approvals-for-all-721-info-severity-key-shard",
  approvalsForAll1155InfoSeverity: "nm-icephishing-bot-approvals-for-all-1155-info-severity-key-shard",
  permissions: "nm-icephishing-bot-permissions-key-shard",
  permissionsInfoSeverity: "nm-icephishing-bot-permissions-info-severity-key-shard",
  transfers: "nm-icephishing-bot-transfers-key-shard",
  transfersLowSeverity: "nm-icephishing-bot-transfers-low-severity-key-shard",
};

const mockCounters = {
  totalPermits: 60000,
  totalApprovals: 100000,
  totalTransfers: 65000,
  totalERC20Approvals: 72000,
  totalERC721Approvals: 10000,
  totalERC721ApprovalsForAll: 8200,
  totalERC1155ApprovalsForAll: 8000,
  detectedPermits: 220,
  detectedPermitsInfo: 56,
  detectedScamPermits: 34,
  detectedScamCreatorPermits: 111,
  detectedSuspiciousPermits: 121,
  detectedERC20Approvals: 78,
  detectedERC20ApprovalsInfo: 99,
  detectedERC721Approvals: 13,
  detectedERC721ApprovalsInfo: 21,
  detectedERC721ApprovalsForAll: 220,
  detectedERC721ApprovalsForAllInfo: 144,
  detectedERC1155ApprovalsForAll: 545,
  detectedERC1155ApprovalsForAllInfo: 11,
  detectedScamApprovals: 6,
  detectedScamCreatorApprovals: 20,
  detectedSuspiciousApprovals: 310,
  detectedTransfers: 77,
  detectedTransfersLow: 313,
  detectedPermittedTransfers: 41,
  detectedPermittedTransfersMedium: 43,
  detectedScamTransfers: 55,
  detectedScamCreatorTransfers: 90,
  detectedSuspiciousTransfers: 120,
};

describe("ice-phishing bot", () => {
  const mockProvider = {
    getCode: jest.fn(),
    getBlockWithTransactions: jest.fn(),
    getTransactionCount: jest.fn(),
    getNetwork: jest.fn(),
  };
  const mockGetSuspiciousContracts = jest.fn();
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
      };
      mockTxEvent.filterLog.mockReset();
      mockTxEvent.filterFunction.mockReset();
      mockProvider.getCode.mockReset();
      mockProvider.getTransactionCount.mockReset();
      mockProvider.getNetwork.mockReturnValue({ chainId: 1 });
      mockProvider.getBlockWithTransactions.mockReturnValue({ transactions: [{ hash: "hash15" }, { hash: "hash25" }] });
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
        MOCK_DATABASE_OBJECTS_KEYS,
        mockPersistenceHelper,
        mockObjects
      );
    });

    it("should return empty findings if there are no Approval & Transfer events and no permit functions", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([]);
      expect(mockTxEvent.filterLog).toHaveBeenCalledTimes(6);
      expect(mockTxEvent.filterFunction).toHaveBeenCalledTimes(2);
    });

    it("should return findings if there is a EIP-2612's permit function call", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      mockTxEvent.filterFunction.mockReturnValueOnce([mockPermitFunctionCall]).mockReturnValueOnce([]);
      mockTxEvent.filterLog.mockReturnValue([]);
      mockProvider.getCode.mockReturnValue("0x");
      const findings = await handleTransaction(mockTxEvent);

      const mockAnomalyScore = mockCounters.detectedPermits / mockCounters.totalPermits;

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Account got permission for ERC-20 tokens",
          description: `${spender} gave permission to ${spender} for ${owner1}'s ERC-20 tokens`,
          alertId: "ICE-PHISHING-ERC20-PERMIT",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            msgSender: spender,
            owner: owner1,
            spender,
            anomalyScore:
              mockAnomalyScore.toFixed(2) === "0.00" ? mockAnomalyScore.toString() : mockAnomalyScore.toFixed(2),
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
      expect(mockTxEvent.filterFunction).toHaveBeenCalledTimes(2);
    });

    it("should return findings if there is a DAI-like permit function call", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([mockDAILikePermitFunctionCall]);
      mockTxEvent.filterLog.mockReturnValue([]);
      mockProvider.getCode.mockReturnValue("0x");
      const findings = await handleTransaction(mockTxEvent);

      const mockAnomalyScore = mockCounters.detectedPermits / mockCounters.totalPermits;

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Account got permission for ERC-20 tokens",
          description: `${spender} gave permission to ${spender} for ${owner1}'s ERC-20 tokens`,
          alertId: "ICE-PHISHING-ERC20-PERMIT",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            msgSender: spender,
            owner: owner1,
            spender,
            anomalyScore:
              mockAnomalyScore.toFixed(2) === "0.00" ? mockAnomalyScore.toString() : mockAnomalyScore.toFixed(2),
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
      expect(mockTxEvent.filterFunction).toHaveBeenCalledTimes(2);
    });

    it("should return a finding if a suspicious contract is involved in a permit function call", async () => {
      const initialize = provideInitialize(
        mockProvider,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters,
        MOCK_DATABASE_OBJECTS_KEYS
      );
      for (const key in MOCK_DATABASE_KEYS) {
        mockPersistenceHelper.load.mockReturnValueOnce(mockCounters[key]);
      }
      await initialize();

      const mockBlockEvent = { block: { number: 876123 } };
      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters
      );

      mockGetSuspiciousContracts.mockResolvedValueOnce(
        new Set([{ address: createAddress("0xabcdabcd"), creator: createAddress("0xeeffeeff") }])
      );
      const axiosResponse = { data: [createAddress("0x5050")] };
      axios.get.mockResolvedValueOnce(axiosResponse);

      await handleBlock(mockBlockEvent);

      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      for (const _ in MOCK_DATABASE_OBJECTS_KEYS) {
        mockPersistenceHelper.load.mockReturnValueOnce({});
      }

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
          expiry: 8359543534435,
        },
      };

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([mockDAILikePermitFunctionCall]);
      mockTxEvent.filterLog.mockReturnValue([]);

      mockProvider.getCode.mockResolvedValueOnce("0x32523523");
      const axiosResponse2 = {
        data: { message: "totally ok", status: "1", result: [{ contractCreator: createAddress("0xbbbb") }] },
      };
      const axiosResponse3 = { data: { message: "totally ok", status: "1", result: [createAddress("0xaaaa")] } };
      axios.get.mockResolvedValue(axiosResponse2).mockResolvedValueOnce(axiosResponse3);
      const findings = await handleTransaction(mockTxEvent);

      const mockAnomalyScore1 = mockCounters.detectedSuspiciousPermits / mockCounters.totalPermits;
      const mockAnomalyScore2 = mockCounters.detectedPermitsInfo / mockCounters.totalPermits;

      expect(findings).toStrictEqual([
        Finding.fromObject({
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
            anomalyScore:
              mockAnomalyScore1.toFixed(2) === "0.00" ? mockAnomalyScore1.toString() : mockAnomalyScore1.toFixed(2),
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
        Finding.fromObject({
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
            anomalyScore:
              mockAnomalyScore2.toFixed(2) === "0.00" ? mockAnomalyScore2.toString() : mockAnomalyScore2.toFixed(2),
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
      expect(mockTxEvent.filterLog).toHaveBeenCalledTimes(6);
      expect(mockTxEvent.filterFunction).toHaveBeenCalledTimes(2);
    });

    it("should return a finding if a creator of a suspicious contract is involved in a permit function call", async () => {
      const initialize = provideInitialize(
        mockProvider,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters,
        MOCK_DATABASE_OBJECTS_KEYS
      );
      for (const key in MOCK_DATABASE_KEYS) {
        mockPersistenceHelper.load.mockReturnValueOnce(mockCounters[key]);
      }
      await initialize();

      const mockBlockEvent = { block: { number: 876126 } };
      const handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters
      );
      // mockGetSuspiciousContracts.mockResolvedValueOnce(
      //   new Set([{ address: createAddress("0xabcdabcd"), creator: createAddress("0xeeffeeff") }])
      // );
      // const axiosResponse = { data: [createAddress("0x5050")] };
      // axios.get.mockResolvedValueOnce(axiosResponse);

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
          expiry: 8359543534435,
        },
      };

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([mockDAILikePermitFunctionCall]);
      mockTxEvent.filterLog.mockReturnValue([]);

      mockProvider.getCode.mockResolvedValueOnce("0x32523523");
      const axiosResponse2 = {
        data: { message: "totally ok", status: "1", result: [{ contractCreator: createAddress("0xbbbb") }] },
      };
      const axiosResponse3 = { data: { message: "totally ok", status: "1", result: [createAddress("0xaaaa")] } };
      axios.get.mockResolvedValue(axiosResponse2).mockResolvedValueOnce(axiosResponse3);
      const findings = await handleTransaction(mockTxEvent);

      const mockAnomalyScore1 = mockCounters.detectedSuspiciousPermits / mockCounters.totalPermits;
      const mockAnomalyScore2 = mockCounters.detectedPermitsInfo / mockCounters.totalPermits;

      expect(findings).toStrictEqual([
        Finding.fromObject({
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
            anomalyScore:
              mockAnomalyScore1.toFixed(2) === "0.00" ? mockAnomalyScore1.toString() : mockAnomalyScore1.toFixed(2),
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
        Finding.fromObject({
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
            anomalyScore:
              mockAnomalyScore2.toFixed(2) === "0.00" ? mockAnomalyScore2.toString() : mockAnomalyScore2.toFixed(2),
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
      expect(mockTxEvent.filterLog).toHaveBeenCalledTimes(6);
      expect(mockTxEvent.filterFunction).toHaveBeenCalledTimes(2);
    });

    it("should return findings if there is a high number of ERC1155 ApprovalForAll events", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      for (const _ in MOCK_DATABASE_OBJECTS_KEYS) {
        mockPersistenceHelper.load.mockReturnValueOnce({});
      }

      const tempTxEvent0 = {
        filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
        filterLog: jest
          .fn()
          .mockReturnValueOnce([]) // ERC20 approvals
          .mockReturnValueOnce([]) // ERC721 approvals
          .mockReturnValueOnce([mockApprovalForAllEvent[0]]) // ApprovalForAll
          .mockReturnValueOnce([]) // ERC20 transfers
          .mockReturnValueOnce([]) // ERC721 transfers
          .mockReturnValueOnce([]), // ERC1155 transfers
        hash: "hash0",
        timestamp: 0,
        from: spender,
      };
      mockProvider.getCode.mockReturnValueOnce("0x992eb2c2d699").mockReturnValueOnce("0x").mockReturnValueOnce("0x");
      mockProvider.getTransactionCount.mockReturnValue(1);
      await handleTransaction(tempTxEvent0);

      expect(mockProvider.getCode).toHaveBeenCalledTimes(3);

      const tempTxEvent1 = {
        filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
        filterLog: jest
          .fn()
          .mockReturnValueOnce([]) // ERC20 approvals
          .mockReturnValueOnce([]) // ERC721 approvals
          .mockReturnValueOnce([mockApprovalForAllEvent[1]]) // ApprovalForAll
          .mockReturnValueOnce([]) // ERC20 transfers
          .mockReturnValueOnce([]) // ERC721 transfers
          .mockReturnValueOnce([]), // ERC1155 transfers
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
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockProvider.getCode.mockReturnValueOnce("0x");
      mockProvider.getTransactionCount.mockReturnValue(1);
      expect(mockProvider.getCode).toHaveBeenCalledTimes(4);
      const findings = await handleTransaction(mockTxEvent);

      const mockAnomalyScore = mockCounters.detectedERC1155ApprovalsForAll / mockCounters.totalERC1155ApprovalsForAll;

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Account got approval for all ERC-1155 tokens",
          description: `${spender} obtained transfer approval for all ERC-1155 tokens from ${owner3}`,
          alertId: "ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            spender,
            owner: owner3,
            anomalyScore:
              mockAnomalyScore.toFixed(2) === "0.00" ? mockAnomalyScore.toString() : mockAnomalyScore.toFixed(2),
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
        MOCK_DATABASE_OBJECTS_KEYS
      );
      for (const key in MOCK_DATABASE_KEYS) {
        mockPersistenceHelper.load.mockReturnValueOnce(mockCounters[key]);
      }
      await initialize();
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      for (let i = 0; i < 2; i++) {
        for (const _ in MOCK_DATABASE_OBJECTS_KEYS) {
          mockPersistenceHelper.load.mockReturnValueOnce({});
        }
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([mockApprovalForAllEvent[i]]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
        };
        mockProvider.getCode.mockReturnValue("0x");

        mockProvider.getTransactionCount.mockReturnValue(1);
        await handleTransaction(tempTxEvent);
      }
      //expect(mockProvider.getCode).toHaveBeenCalledTimes(4);

      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([mockApprovalForAllEvent[2]]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockProvider.getCode.mockReturnValue("0x");
      mockProvider.getTransactionCount.mockReturnValue(1);

      const findings = await handleTransaction(mockTxEvent);

      const mockAnomalyScore = mockCounters.detectedERC721ApprovalsForAll / mockCounters.totalERC721ApprovalsForAll;

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Account got approval for all ERC-721 tokens",
          description: `${spender} obtained transfer approval for all ERC-721 tokens from ${owner3}`,
          alertId: "ICE-PHISHING-ERC721-APPROVAL-FOR-ALL",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            spender,
            owner: owner3,
            anomalyScore:
              mockAnomalyScore.toFixed(2) === "0.00" ? mockAnomalyScore.toString() : mockAnomalyScore.toFixed(2),
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
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([thisMockApprovalForAllEvent[i]]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
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
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockProvider.getCode.mockReturnValue("0x");
      mockProvider.getTransactionCount.mockReturnValue(1234454);
      expect(mockProvider.getCode).toHaveBeenCalledTimes(4);
      const findings = await handleTransaction(mockTxEvent);

      const mockAnomalyScore = mockCounters.detectedERC721ApprovalsForAllInfo / mockCounters.totalERC721ApprovalsForAll;

      expect(findings).toStrictEqual([
        Finding.fromObject({
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
            anomalyScore:
              mockAnomalyScore.toFixed(2) === "0.00" ? mockAnomalyScore.toString() : mockAnomalyScore.toFixed(2),
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
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([mockApprovalERC20Events[i]]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
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
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockProvider.getCode.mockReturnValue("0x");
      expect(mockProvider.getCode).toHaveBeenCalledTimes(3);
      const findings = await handleTransaction(mockTxEvent);

      const mockAnomalyScore = mockCounters.detectedERC20Approvals / mockCounters.totalERC20Approvals;

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "High number of accounts granted approvals for ERC-20 tokens",
          description: `${spender} obtained transfer approval for 1 ERC-20 tokens by 3 accounts over period of 1 days.`,
          alertId: "ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            firstTxHash: "hash0",
            lastTxHash: "hash2",
            anomalyScore:
              mockAnomalyScore.toFixed(2) === "0.00" ? mockAnomalyScore.toString() : mockAnomalyScore.toFixed(2),
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
        }),
      ]);
    });

    it("should return findings if there is a high number of ERC721 Approval events", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      for (let i = 0; i < 2; i++) {
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValue([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([mockApprovalERC721Events[i]]) // ERC721 approvals
            .mockReturnValue([]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
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
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);

      const findings = await handleTransaction(mockTxEvent);

      const mockAnomalyScore = mockCounters.detectedERC721Approvals / mockCounters.totalERC721Approvals;

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "High number of accounts granted approvals for ERC-721 tokens",
          description: `${spender} obtained transfer approval for 1 ERC-721 tokens by 3 accounts over period of 1 days.`,
          alertId: "ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            firstTxHash: "hash0",
            lastTxHash: "hash2",
            anomalyScore:
              mockAnomalyScore.toFixed(2) === "0.00" ? mockAnomalyScore.toString() : mockAnomalyScore.toFixed(2),
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
        }),
      ]);
    });

    it("should return findings if there is a high number of ERC721 Approval events regarding a verified contract", async () => {
      const initialize = provideInitialize(
        mockProvider,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters,
        MOCK_DATABASE_OBJECTS_KEYS
      );
      for (const key in MOCK_DATABASE_KEYS) {
        mockPersistenceHelper.load.mockReturnValueOnce(mockCounters[key]);
      }

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
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      for (let i = 0; i < 3; i++) {
        for (const _ in MOCK_DATABASE_OBJECTS_KEYS) {
          mockPersistenceHelper.load.mockReturnValueOnce({});
        }
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValue([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([thisMockApprovalERC721Events[i]]) // ERC721 approvals
            .mockReturnValue([]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
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

      for (const _ in MOCK_DATABASE_OBJECTS_KEYS) {
        mockPersistenceHelper.load.mockReturnValueOnce({});
      }

      mockTxEvent.blockNumber = 23;
      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([thisMockApprovalERC721Events[2]]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);

      const findings = await handleTransaction(mockTxEvent);

      const mockAnomalyScore = mockCounters.detectedERC721ApprovalsInfo / mockCounters.totalERC721Approvals;

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "High number of accounts granted approvals for ERC-721 tokens",
          description: `${spender} obtained transfer approval for 1 ERC-721 tokens by 3 accounts over period of 1 days.`,
          alertId: "ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS-INFO",
          severity: FindingSeverity.Info,
          type: FindingType.Info,
          metadata: {
            firstTxHash: "hash0",
            lastTxHash: "hash2",
            anomalyScore:
              mockAnomalyScore.toFixed(2) === "0.00" ? mockAnomalyScore.toString() : mockAnomalyScore.toFixed(2),
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
        }),
      ]);
    });

    it("should not return findings if there is a high number of ERC721 Approval events regarding a verified contract with high number of past transactions", async () => {
      const initialize = provideInitialize(
        mockProvider,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters,
        MOCK_DATABASE_OBJECTS_KEYS
      );
      for (const key in MOCK_DATABASE_KEYS) {
        mockPersistenceHelper.load.mockReturnValueOnce(mockCounters[key]);
      }

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
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      for (let i = 0; i < 3; i++) {
        for (const _ in MOCK_DATABASE_OBJECTS_KEYS) {
          mockPersistenceHelper.load.mockReturnValueOnce({});
        }
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValue([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([thisMockApprovalERC721Events[i]]) // ERC721 approvals
            .mockReturnValue([]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
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
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);

      const findings = await handleTransaction(mockTxEvent);
      expect(findings).toStrictEqual([]);
    });

    it("should return findings if there is a high number of ERC-20 Transfer events and the balance is completely drained", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      // Create the Approval events first
      for (let i = 0; i < 3; i++) {
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([mockApprovalERC20Events[i]]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
        };
        mockProvider.getCode.mockReturnValue("0x");

        await handleTransaction(tempTxEvent);
      }

      for (let i = 0; i < 2; i++) {
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([mockApprovalERC20Events[i]]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([]) // ApprovalForAll
            .mockReturnValueOnce([mockTransferEvents[i]]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
          hash: `hash${i}`,
          timestamp: 3000 + 1000 * i,
          from: spender,
        };

        await handleTransaction(tempTxEvent);
      }

      mockTxEvent.filterLog
        .mockReturnValueOnce([mockApprovalERC20Events[2]]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([mockTransferEvents[2]]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockBalanceOf.mockResolvedValueOnce(ethers.BigNumber.from(0));

      const findings = await handleTransaction(mockTxEvent);

      const mockAnomalyScore = mockCounters.detectedTransfers / mockCounters.totalTransfers;

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Previously approved assets transferred",
          description: `${spender} transferred 1 assets from 3 accounts over period of 1 days.`,
          alertId: "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS",
          severity: FindingSeverity.High,
          type: FindingType.Exploit,
          metadata: {
            firstTxHash: "hash0",
            lastTxHash: "hash2",
            anomalyScore:
              mockAnomalyScore.toFixed(2) === "0.00" ? mockAnomalyScore.toString() : mockAnomalyScore.toFixed(2),
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
        }),
      ]);
    });

    it("should not return findings if there is a high number of ERC-20 Transfer events but the balance is not completely drained", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      // Create the Approval events first
      for (let i = 0; i < 3; i++) {
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([mockApprovalERC20Events2[i]]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
        };
        mockProvider.getCode.mockReturnValue("0x");

        await handleTransaction(tempTxEvent);
      }

      for (let i = 0; i < 2; i++) {
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([mockApprovalERC20Events2[i]]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([]) // ApprovalForAll
            .mockReturnValueOnce([mockTransferEvents2[i]]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
          hash: `hash${i}`,
          timestamp: 3000 + 1000 * i,
          from: spender,
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
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockBalanceOf.mockResolvedValue(ethers.BigNumber.from("100000000000000")); // not drained
      expect(mockProvider.getCode).toHaveBeenCalledTimes(4);

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([]);
    });

    it("should return findings if there is a high number of ERC-721 Transfer events", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      // Create the Approval events first
      for (let i = 0; i < 3; i++) {
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([mockApprovalERC721Events[i]]) // ERC721 approvals
            .mockReturnValueOnce([]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
        };
        mockProvider.getCode.mockReturnValue("0x");

        await handleTransaction(tempTxEvent);
      }

      for (let i = 0; i < 2; i++) {
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([mockApprovalERC721Events[i]]) // ERC721 approvals
            .mockReturnValueOnce([]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([mockTransferERC721Events[i]]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
          hash: `hash${i}`,
          timestamp: 3000 + 1000 * i,
          from: spender,
        };

        await handleTransaction(tempTxEvent);
      }

      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([mockApprovalERC721Events[2]]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([mockTransferERC721Events[2]]) // ERC721 transfers
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      expect(mockProvider.getCode).toHaveBeenCalledTimes(4);

      const findings = await handleTransaction(mockTxEvent);

      const mockAnomalyScore = mockCounters.detectedTransfers / mockCounters.totalTransfers;

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Previously approved assets transferred",
          description: `${spender} transferred 1 assets from 3 accounts over period of 1 days.`,
          alertId: "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS",
          severity: FindingSeverity.High,
          type: FindingType.Exploit,
          metadata: {
            firstTxHash: "hash0",
            lastTxHash: "hash2",
            anomalyScore:
              mockAnomalyScore.toFixed(2) === "0.00" ? mockAnomalyScore.toString() : mockAnomalyScore.toFixed(2),
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
        }),
      ]);
    });

    it("should return findings if there is a high number of ERC-1155 TransferSingle events and the balance is completely drained", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      // Create the Approval events first
      for (let i = 0; i < 3; i++) {
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([mockApprovalForAllEvent[i]]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
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
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([mockApprovalForAllEvent[i]]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([mockTransferSingleEvents[i]]), // ERC1155 transfers
          hash: `hash${i}`,
          timestamp: 3000 + 1000 * i,
          from: spender,
        };
        await handleTransaction(tempTxEvent);
      }

      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([mockApprovalForAllEvent[2]]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([mockTransferSingleEvents[2]]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockBalanceOf.mockResolvedValueOnce(ethers.BigNumber.from(0));
      expect(mockProvider.getCode).toHaveBeenCalledTimes(6);

      const findings = await handleTransaction(mockTxEvent);

      const mockAnomalyScore = mockCounters.detectedERC1155ApprovalsForAll / mockCounters.totalERC1155ApprovalsForAll;
      const mockAnomalyScore2 = mockCounters.detectedTransfers / mockCounters.totalTransfers;

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Account got approval for all ERC-1155 tokens",
          description: `${spender} obtained transfer approval for all ERC-1155 tokens from ${owner3}`,
          alertId: "ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            spender,
            owner: owner3,
            anomalyScore:
              mockAnomalyScore.toFixed(2) === "0.00" ? mockAnomalyScore.toString() : mockAnomalyScore.toFixed(2),
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
        Finding.fromObject({
          name: "Previously approved assets transferred",
          description: `${spender} transferred 1 assets from 3 accounts over period of 1 days.`,
          alertId: "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS",
          severity: FindingSeverity.High,
          type: FindingType.Exploit,
          metadata: {
            firstTxHash: "hash0",
            lastTxHash: "hash2",
            anomalyScore:
              mockAnomalyScore2.toFixed(2) === "0.00" ? mockAnomalyScore2.toString() : mockAnomalyScore2.toFixed(2),
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
        }),
      ]);
    });

    it("should return findings if there is a high number of ERC-1155 TransferBatch events and the balance is completely drained", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      // Create the Approval events first
      for (let i = 0; i < 3; i++) {
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([mockApprovalForAllEvent[i]]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
        };
        mockProvider.getCode.mockReturnValueOnce("0x992eb2c2d699").mockReturnValue("0x");

        await handleTransaction(tempTxEvent);
      }

      for (let i = 0; i < 2; i++) {
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([mockApprovalForAllEvent[i]]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([mockTransferBatchEvents[i]]), // ERC1155 transfers
          hash: `hash${i}`,
          timestamp: 3000 + 1000 * i,
          from: spender,
        };

        await handleTransaction(tempTxEvent);
      }

      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([mockApprovalForAllEvent[2]]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([mockTransferBatchEvents[2]]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockBalanceOf.mockResolvedValue(ethers.BigNumber.from(0));
      expect(mockProvider.getCode).toHaveBeenCalledTimes(6);

      const findings = await handleTransaction(mockTxEvent);

      const mockAnomalyScore = mockCounters.detectedERC1155ApprovalsForAll / mockCounters.totalERC1155ApprovalsForAll;
      const mockAnomalyScore2 = mockCounters.detectedTransfers / mockCounters.totalTransfers;

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Account got approval for all ERC-1155 tokens",
          description: `${spender} obtained transfer approval for all ERC-1155 tokens from ${owner3}`,
          alertId: "ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            spender,
            owner: owner3,
            anomalyScore:
              mockAnomalyScore.toFixed(2) === "0.00" ? mockAnomalyScore.toString() : mockAnomalyScore.toFixed(2),
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

        Finding.fromObject({
          name: "Previously approved assets transferred",
          description: `${spender} transferred 1 assets from 3 accounts over period of 1 days.`,
          alertId: "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS",
          severity: FindingSeverity.High,
          type: FindingType.Exploit,
          metadata: {
            firstTxHash: "hash0",
            lastTxHash: "hash2",
            anomalyScore:
              mockAnomalyScore2.toFixed(2) === "0.00" ? mockAnomalyScore2.toString() : mockAnomalyScore2.toFixed(2),
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
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([mockApprovalForAllEvent[i]]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
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
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([mockApprovalForAllEvent[i]]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([mockTransferBatchEvents[i]]), // ERC1155 transfers
          hash: `hash${i}`,
          timestamp: 3000 + 1000 * i,
          from: spender,
        };

        await handleTransaction(tempTxEvent);
      }
      const mockTxEvent = {
        filterLog: jest.fn(),
        filterFunction: jest.fn(),
        hash: "hash2",
        timestamp: 10000,
        from: spender,
      };

      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([mockApprovalForAllEvent[2]]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([mockTransferBatchEvents[2]]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockBalanceOf.mockResolvedValue(ethers.BigNumber.from(0));

      expect(mockProvider.getCode).toHaveBeenCalledTimes(6);

      const findings = await handleTransaction(mockTxEvent);

      const mockAnomalyScore =
        mockCounters.detectedERC1155ApprovalsForAllInfo / mockCounters.totalERC1155ApprovalsForAll;
      const mockAnomalyScore2 = mockCounters.detectedTransfersLow / mockCounters.totalTransfers;

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Account got approval for all ERC-1155 tokens",
          description: `${spender} obtained transfer approval for all ERC-1155 tokens from ${owner3}`,
          alertId: "ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL-INFO",
          severity: FindingSeverity.Info,
          type: FindingType.Info,
          metadata: {
            spender,
            owner: owner3,
            anomalyScore:
              mockAnomalyScore.toFixed(2) === "0.00" ? mockAnomalyScore.toString() : mockAnomalyScore.toFixed(2),
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
        Finding.fromObject({
          name: "Previously approved assets transferred",
          description: `${spender} transferred 1 assets from 3 accounts over period of 1 days.`,
          alertId: "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS-LOW",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            firstTxHash: "hash0",
            lastTxHash: "hash2",
            anomalyScore:
              mockAnomalyScore2.toFixed(2) === "0.00" ? mockAnomalyScore2.toString() : mockAnomalyScore2.toFixed(2),
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
          ],
        }),
      ]);
    });

    it("should return findings if there's a transfer following an EIP-2612's permit function call", async () => {
      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

      const tempTxEvent = {
        filterFunction: jest.fn().mockReturnValueOnce([mockPermitFunctionCall]).mockReturnValueOnce([]),
        filterLog: jest
          .fn()
          .mockReturnValueOnce([]) // ERC20 approvals
          .mockReturnValueOnce([]) // ERC721 approvals
          .mockReturnValueOnce([]) // ApprovalForAll
          .mockReturnValueOnce([]) // ERC20 transfers
          .mockReturnValueOnce([]) // ERC721 transfers
          .mockReturnValueOnce([]), // ERC1155 transfers
        hash: "hash33",
        timestamp: 1001,
        from: spender,
      };
      mockProvider.getCode.mockReturnValue("0x");

      await handleTransaction(tempTxEvent);

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([mockTransferEvents[0]]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockBalanceOf.mockResolvedValueOnce(ethers.BigNumber.from(0));

      const findings = await handleTransaction(mockTxEvent);

      const mockAnomalyScore = mockCounters.detectedPermittedTransfers / mockCounters.totalTransfers;

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Previously permitted assets transferred",
          description: `${spender} transferred ${mockTransferEvents[0].args.value} tokens from ${owner1} to ${mockTransferEvents[0].args.to}`,
          alertId: "ICE-PHISHING-PERMITTED-ERC20-TRANSFER",
          severity: FindingSeverity.Critical,
          type: FindingType.Exploit,
          metadata: {
            owner: owner1,
            receiver: mockTransferEvents[0].args.to,
            spender: spender,
            anomalyScore:
              mockAnomalyScore.toFixed(2) === "0.00" ? mockAnomalyScore.toString() : mockAnomalyScore.toFixed(2),
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
        filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([mockDAILikePermitFunctionCall]),
        filterLog: jest
          .fn()
          .mockReturnValueOnce([]) // ERC20 approvals
          .mockReturnValueOnce([]) // ERC721 approvals
          .mockReturnValueOnce([]) // ApprovalForAll
          .mockReturnValueOnce([]) // ERC20 transfers
          .mockReturnValueOnce([]) // ERC721 transfers
          .mockReturnValueOnce([]), // ERC1155 transfers
        hash: "hash33",
        timestamp: 1001,
        from: spender,
      };
      mockProvider.getCode.mockReturnValue("0x");

      await handleTransaction(tempTxEvent);

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([mockTransferEvents[0]]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockBalanceOf.mockResolvedValueOnce(ethers.BigNumber.from(0));

      const findings = await handleTransaction(mockTxEvent);

      const mockAnomalyScore = mockCounters.detectedPermittedTransfers / mockCounters.totalTransfers;

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Previously permitted assets transferred",
          description: `${spender} transferred ${mockTransferEvents[0].args.value} tokens from ${owner1} to ${mockTransferEvents[0].args.to}`,
          alertId: "ICE-PHISHING-PERMITTED-ERC20-TRANSFER",
          severity: FindingSeverity.Critical,
          type: FindingType.Exploit,
          metadata: {
            owner: owner1,
            receiver: mockTransferEvents[0].args.to,
            spender: spender,
            anomalyScore:
              mockAnomalyScore.toFixed(2) === "0.00" ? mockAnomalyScore.toString() : mockAnomalyScore.toFixed(2),
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
      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters
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

      for (const _ in MOCK_DATABASE_OBJECTS_KEYS) {
        mockPersistenceHelper.load.mockReturnValueOnce({});
      }

      mockTxEvent.filterFunction.mockReturnValueOnce([mockPermitFunctionCall]).mockReturnValueOnce([]);
      mockTxEvent.filterLog.mockReturnValue([]);
      mockProvider.getCode.mockReturnValue("0x");

      const axiosResponse2 = { data: { "www.scamDomain.com": [createAddress("0x5050")] } };
      axios.get.mockResolvedValueOnce(axiosResponse2);
      const findings = await handleTransaction(mockTxEvent);

      const mockAnomalyScore = mockCounters.detectedScamPermits / mockCounters.totalPermits;

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Known scam address was involved in an ERC-20 permission",
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
            anomalyScore:
              mockAnomalyScore.toFixed(2) === "0.00" ? mockAnomalyScore.toString() : mockAnomalyScore.toFixed(2),
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
        MOCK_DATABASE_OBJECTS_KEYS
      );
      await initialize();

      const mockBlockEvent = { block: { timestamp: 1000121 } };
      const axiosResponse = { data: [createAddress("0x215050")] };
      axios.get.mockResolvedValueOnce(axiosResponse);
      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters
      );
      await handleBlock(mockBlockEvent);

      mockPersistenceHelper.load.mockReturnValueOnce(mockObjects);

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

      mockTxEvent.filterFunction.mockReturnValueOnce([mockPermitFunctionCall]).mockReturnValueOnce([]);
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

      const findings = await handleTransaction(mockTxEvent);

      const mockAnomalyScore1 = mockCounters.detectedScamCreatorPermits / mockCounters.totalPermits;
      const mockAnomalyScore2 = mockCounters.detectedPermitsInfo / mockCounters.totalPermits;

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Contract created by a known scam address was involved in an ERC-20 permission",
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
            anomalyScore:
              mockAnomalyScore1.toFixed(2) === "0.00" ? mockAnomalyScore1.toString() : mockAnomalyScore1.toFixed(2),
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
        Finding.fromObject({
          name: "Account got permission for ERC-20 tokens",
          description: `${spender} gave permission to ${createAddress("0x23325050")} for ${owner1}'s ERC-20 tokens`,
          alertId: "ICE-PHISHING-ERC20-PERMIT-INFO",
          severity: FindingSeverity.Info,
          type: FindingType.Info,
          metadata: {
            msgSender: spender,
            spender: createAddress("0x23325050"),
            owner: owner1,
            anomalyScore:
              mockAnomalyScore2.toFixed(2) === "0.00" ? mockAnomalyScore2.toString() : mockAnomalyScore2.toFixed(2),
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
      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters
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
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);

      const axiosResponse2 = { data: { "www.scamDomain.com": [spender] } };
      axios.get.mockResolvedValueOnce(axiosResponse2);
      mockProvider.getCode.mockReturnValue("0x");

      const findings = await handleTransaction(mockTxEvent);

      const mockAnomalyScore = mockCounters.detectedScamApprovals / mockCounters.totalApprovals;

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Known scam address got approval to spend assets",
          description: `Scam address ${spender} got approval for ${owner1}'s assets`,
          alertId: "ICE-PHISHING-SCAM-APPROVAL",
          severity: FindingSeverity.High,
          type: FindingType.Suspicious,
          metadata: {
            scamDomains: ["www.scamDomain.com"],
            scamSpender: spender,
            owner: owner1,
            anomalyScore:
              mockAnomalyScore.toFixed(2) === "0.00" ? mockAnomalyScore.toString() : mockAnomalyScore.toFixed(2),
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
      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters
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
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockProvider.getCode.mockReturnValue("0x");

      const findings = await handleTransaction(mockTxEvent);

      const mockAnomalyScore = mockCounters.detectedScamTransfers / mockCounters.totalTransfers;

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Known scam address was involved in an asset transfer",
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
            anomalyScore:
              mockAnomalyScore.toFixed(2) === "0.00" ? mockAnomalyScore.toString() : mockAnomalyScore.toFixed(2),
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
        MOCK_DATABASE_OBJECTS_KEYS
      );
      for (const key in MOCK_DATABASE_KEYS) {
        mockPersistenceHelper.load.mockReturnValueOnce(mockCounters[key]);
      }
      await initialize();

      const suspiciousReceiver = createChecksumAddress("0xabcdabcd");
      const suspiciousContractCreator = createChecksumAddress("0xfefefe");

      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters
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
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockProvider.getCode.mockReturnValue("0x333");

      const axiosResponse2 = {
        data: { message: "okkk", status: "1", result: [{ contractCreator: createAddress("0xaaaabbb") }] },
      };
      axios.get.mockResolvedValue(axiosResponse2);

      const findings = await handleTransaction(mockTxEvent);

      const mockAnomalyScore = mockCounters.detectedSuspiciousTransfers / mockCounters.totalTransfers;

      expect(findings).toStrictEqual([
        Finding.fromObject({
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
            anomalyScore:
              mockAnomalyScore.toFixed(2) === "0.00" ? mockAnomalyScore.toString() : mockAnomalyScore.toFixed(2),
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
        MOCK_DATABASE_OBJECTS_KEYS
      );
      for (const key in MOCK_DATABASE_KEYS) {
        mockPersistenceHelper.load.mockReturnValueOnce(mockCounters[key]);
      }
      await initialize();
      const suspiciousContract = createChecksumAddress("0xabcdabcd");
      const suspiciousContractCreator = createChecksumAddress("0xfefefe");
      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters
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
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockProvider.getCode.mockReturnValue("0x333");

      const axiosResponse2 = {
        data: { message: "okkk", status: "1", result: [{ contractCreator: createAddress("0xaaaabbb") }] },
      };
      axios.get.mockResolvedValue(axiosResponse2);

      const findings = await handleTransaction(mockTxEvent);

      const mockAnomalyScore = mockCounters.detectedSuspiciousTransfers / mockCounters.totalTransfers;

      expect(findings).toStrictEqual([
        Finding.fromObject({
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
            anomalyScore:
              mockAnomalyScore.toFixed(2) === "0.00" ? mockAnomalyScore.toString() : mockAnomalyScore.toFixed(2),
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

      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters
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
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockProvider.getCode.mockReturnValue("0x");

      const findings = await handleTransaction(mockTxEvent);

      const mockAnomalyScore = mockCounters.detectedSuspiciousApprovals / mockCounters.totalApprovals;

      expect(findings).toStrictEqual([
        Finding.fromObject({
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
            anomalyScore:
              mockAnomalyScore.toFixed(2) === "0.00" ? mockAnomalyScore.toString() : mockAnomalyScore.toFixed(2),
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
  });

  describe("handleBlock", () => {
    const timePeriod = 2 * timePeriodDays * 24 * 60 * 60;

    beforeEach(() => {
      resetLastTimestamp();
      resetInit();
      Object.keys(mockObjects).forEach((s) => {
        mockObjects[s] = {};
      });
      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters,
        mockObjects
      );
    });

    afterEach(async () => {
      mockPersistenceHelper.persist.mockClear();
    });

    it("should do nothing if enough time has not passed", async () => {
      const axiosResponse = { data: [createAddress("0x5050")] };
      axios.get.mockResolvedValue(axiosResponse);
      const mockBlockEvent = { block: { timestamp: 1000 } };
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
    });

    it("should not delete the entry if it was updated recently/permission deadline has not passed", async () => {
      const axiosResponse = { data: [createAddress("0x5050")] };
      axios.get.mockResolvedValue(axiosResponse);
      const mockBlockEvent = { block: { timestamp: timePeriod } };
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

      await handleBlock(mockBlockEvent);

      expect(Object.keys(mockObjects.approvals).length).toStrictEqual(0);
      expect(Object.keys(mockObjects.approvalsERC20).length).toStrictEqual(0);
      expect(Object.keys(mockObjects.approvalsERC721).length).toStrictEqual(0);
      expect(Object.keys(mockObjects.approvalsForAll721).length).toStrictEqual(0);
      expect(Object.keys(mockObjects.approvalsForAll1155).length).toStrictEqual(0);
      expect(Object.keys(mockObjects.permissions).length).toStrictEqual(0);
      expect(Object.keys(mockObjects.transfers).length).toStrictEqual(0);
    });

    it("should populate the suspicious contracts set correctly", async () => {
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

      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters,
        mockObjects
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

      expect(mockPersistenceHelper.persist).toHaveBeenCalledTimes(30);
    });

    it("should not persist values because block is not evenly divisible by 240", async () => {
      const axiosResponse = { data: [createAddress("0x5050")] };
      axios.get.mockResolvedValue(axiosResponse);

      handleBlock = provideHandleBlock(
        mockGetSuspiciousContracts,
        mockPersistenceHelper,
        MOCK_DATABASE_KEYS,
        mockCounters
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

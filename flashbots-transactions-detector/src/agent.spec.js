const { FindingType, FindingSeverity, Finding, Label, EntityType } = require("forta-agent");
const axios = require("axios");
const { provideHandleBlock, resetLastBlockNumber, provideInitialize } = require("./agent");
const { createAddress } = require("forta-agent-tools");

const from0 = createAddress("0xf0");
const to0 = createAddress("0xb0");
const from1 = createAddress("0xf1");
const to1 = createAddress("0xb1");
const from2 = createAddress("0xf2");
const to2 = createAddress("0xb2");
const from3 = createAddress("0xf3");
const to3 = createAddress("0xb3");
const from4 = createAddress("0xf4");
const to4 = createAddress("0xb4");

const block1 = {
  block_number: 1,
  transactions: [
    {
      eoa_address: from1,
      to_address: to1,
      transaction_hash: "0x1",
      bundle_type: "flashbots",
    },
  ],
};

const block2 = {
  block_number: 2,
  transactions: [
    {
      eoa_address: from2,
      to_address: to2,
      transaction_hash: "0x2",
      bundle_type: "flashbots",
    },
    {
      eoa_address: from3,
      to_address: to3,
      transaction_hash: "0x3",
      bundle_type: "flashbots",
    },
  ],
};

const block3 = {
  block_number: 3,
  transactions: [
    {
      eoa_address: from0,
      to_address: to0,
      transaction_hash: "0x5",
      bundle_type: "mempool",
    },
    {
      eoa_address: from2,
      to_address: to2,
      transaction_hash: "0x2",
      bundle_type: "flashbots",
    },
    {
      eoa_address: from3,
      to_address: to3,
      transaction_hash: "0x3",
      bundle_type: "flashbots",
    },
    {
      eoa_address: from4,
      to_address: to4,
      transaction_hash: "0x4",
      bundle_type: "mempool",
    },
  ],
};

jest.mock("axios");

const mockGetTransactionReceipt = jest.fn();

const mockFlashbotsTxnsKey = "mock-nm-flashbots-bot-txs-key";
const mockTotalTxnsKey = "mock-nm-flashbots-bot-total-txs-key";

let mockTotalFlashbotsTxns = 121;
let mockTotalTxns = 2420;

describe("flashbots transactions detection bot", () => {
  let handleBlock;
  let initialize;
  const mockPersistenceHelper = {
    persist: jest.fn(),
    load: jest.fn(),
  };

  beforeEach(async () => {
    initialize = provideInitialize(mockPersistenceHelper, mockFlashbotsTxnsKey, mockTotalTxnsKey);
    mockPersistenceHelper.load.mockReturnValueOnce(mockTotalFlashbotsTxns).mockReturnValueOnce(mockTotalTxns);
    await initialize();
    handleBlock = provideHandleBlock(
      mockGetTransactionReceipt,
      mockPersistenceHelper,
      mockFlashbotsTxnsKey,
      mockTotalTxnsKey
    );
    mockGetTransactionReceipt.mockReset();
    resetLastBlockNumber();
  });

  afterEach(() => {
    mockPersistenceHelper.persist.mockClear();
  });

  it("should return empty findings if there are no new flashbots blocks", async () => {
    // Flashbots API always returns the last X blocks
    // We process block1 and check if we will process it again
    const response = { data: { blocks: [block1] } };
    const logs = [];

    axios.get.mockResolvedValueOnce(response);
    mockGetTransactionReceipt.mockResolvedValueOnce({ logs });
    const mockBlockEvent1 = {
      block: {
        transactions: ["0x1"],
      },
    };
    await handleBlock(mockBlockEvent1);

    axios.get.mockResolvedValueOnce(response);

    const mockBlockEvent2 = {
      block: {
        transactions: ["0x2"],
      },
    };
    const findings = await handleBlock(mockBlockEvent2);

    expect(findings).toStrictEqual([]);
    expect(mockGetTransactionReceipt).toHaveBeenCalledTimes(1);
  });

  it("should not crash if the API call returns an error", async () => {
    const error = { code: "some error" };
    const logs = [];
    const response = { data: { blocks: [block1] } };

    axios.get.mockRejectedValueOnce(error);
    const mockBlockEvent1 = {
      block: {
        transactions: ["0x1", "0x2"],
      },
    };
    await handleBlock(mockBlockEvent1);

    axios.get.mockResolvedValueOnce(response);
    mockGetTransactionReceipt.mockResolvedValueOnce({ logs });

    const mockBlockEvent2 = {
      block: {
        transactions: ["0x3", "0x4"],
      },
    };
    const mockAnomalyScore = (mockTotalFlashbotsTxns + 1) / (mockTotalTxns + 4);

    const findings = await handleBlock(mockBlockEvent2);

    expect(findings).toStrictEqual([
      Finding.fromObject({
        name: "Flashbots transactions",
        description: `${from1} interacted with ${to1} in a flashbots transaction`,
        alertId: "FLASHBOTS-TRANSACTIONS",
        severity: FindingSeverity.Low,
        type: FindingType.Info,
        metadata: {
          from: from1,
          to: to1,
          hash: "0x1",
          blockNumber: block1.block_number,
          anomalyScore: mockAnomalyScore.toFixed(2),
        },
        labels: [
          Label.fromObject({
            entity: "0x1",
            entityType: EntityType.Transaction,
            label: "Flashbots Transaction",
            confidence: 1,
          }),
        ],
      }),
    ]);
    expect(mockGetTransactionReceipt).toHaveBeenCalledTimes(1);
  });

  it("should return findings if there are new flashbots blocks", async () => {
    const response1 = { data: { blocks: [block1] } };
    const logs1 = [];
    mockGetTransactionReceipt.mockResolvedValueOnce({ logs: logs1 });
    axios.get.mockResolvedValueOnce(response1);
    const mockBlockEvent1 = {
      block: {
        transactions: ["0x1", "0x2", "0x3"],
      },
    };
    await handleBlock(mockBlockEvent1);

    // Only block2 should be processed
    const response2 = { data: { blocks: [block1, block2] } };
    const logs2 = [{ address: to2 }];
    const logs3 = [{ address: to3 }];
    mockGetTransactionReceipt.mockResolvedValueOnce({ logs: logs2 });
    mockGetTransactionReceipt.mockResolvedValueOnce({ logs: logs3 });
    axios.get.mockResolvedValueOnce(response2);

    const mockBlockEvent2 = {
      block: {
        transactions: ["0x4", "0x5", "0x6", "0x7"],
      },
    };
    const mockAnomalyScore1 = (mockTotalFlashbotsTxns + 2) / (mockTotalTxns + 7);
    const mockAnomalyScore2 = (mockTotalFlashbotsTxns + 3) / (mockTotalTxns + 7);

    const findings = await handleBlock(mockBlockEvent2);

    expect(findings).toStrictEqual([
      Finding.fromObject({
        name: "Flashbots transactions",
        description: `${from2} interacted with ${to2} in a flashbots transaction`,
        alertId: "FLASHBOTS-TRANSACTIONS",
        severity: FindingSeverity.Low,
        type: FindingType.Info,
        addresses: [to2],
        metadata: {
          from: from2,
          to: to2,
          hash: "0x2",
          blockNumber: block2.block_number,
          anomalyScore: mockAnomalyScore1.toFixed(2),
        },
        labels: [
          Label.fromObject({
            entity: "0x2",
            entityType: EntityType.Transaction,
            label: "Flashbots Transaction",
            confidence: 1,
          }),
        ],
      }),
      Finding.fromObject({
        name: "Flashbots transactions",
        description: `${from3} interacted with ${to3} in a flashbots transaction`,
        alertId: "FLASHBOTS-TRANSACTIONS",
        severity: FindingSeverity.Low,
        type: FindingType.Info,
        addresses: [to3],
        metadata: {
          from: from3,
          to: to3,
          hash: "0x3",
          blockNumber: block2.block_number,
          anomalyScore: mockAnomalyScore2.toFixed(2),
        },
        labels: [
          Label.fromObject({
            entity: "0x3",
            entityType: EntityType.Transaction,
            label: "Flashbots Transaction",
            confidence: 1,
          }),
        ],
      }),
    ]);
    expect(mockGetTransactionReceipt).toHaveBeenCalledTimes(3);
  });

  it("should filter out 2 mempool transactions and return 2 findings for the flashbots transactions", async () => {
    const response = { data: { blocks: [block3] } };
    const logs = [{ address: to2 }];
    const logs2 = [{ address: to3 }];
    mockGetTransactionReceipt.mockResolvedValueOnce({ logs: logs });
    mockGetTransactionReceipt.mockResolvedValueOnce({ logs: logs2 });
    axios.get.mockResolvedValueOnce(response);
    const mockBlockEvent1 = {
      block: {
        transactions: ["0x1", "0x2", "0x3"],
      },
    };

    const mockAnomalyScore1 = (mockTotalFlashbotsTxns + 1) / (mockTotalTxns + 3);
    const mockAnomalyScore2 = (mockTotalFlashbotsTxns + 2) / (mockTotalTxns + 3);

    const findings = await handleBlock(mockBlockEvent1);

    expect(findings).toStrictEqual([
      Finding.fromObject({
        name: "Flashbots transactions",
        description: `${from2} interacted with ${to2} in a flashbots transaction`,
        alertId: "FLASHBOTS-TRANSACTIONS",
        severity: FindingSeverity.Low,
        type: FindingType.Info,
        addresses: [to2],
        metadata: {
          from: from2,
          to: to2,
          hash: "0x2",
          blockNumber: block3.block_number,
          anomalyScore: mockAnomalyScore1.toFixed(2),
        },
        labels: [
          Label.fromObject({
            entity: "0x2",
            entityType: EntityType.Transaction,
            label: "Flashbots Transaction",
            confidence: 1,
          }),
        ],
      }),
      Finding.fromObject({
        name: "Flashbots transactions",
        description: `${from3} interacted with ${to3} in a flashbots transaction`,
        alertId: "FLASHBOTS-TRANSACTIONS",
        severity: FindingSeverity.Low,
        type: FindingType.Info,
        addresses: [to3],
        metadata: {
          from: from3,
          to: to3,
          hash: "0x3",
          blockNumber: block3.block_number,
          anomalyScore: mockAnomalyScore2.toFixed(2),
        },
        labels: [
          Label.fromObject({
            entity: "0x3",
            entityType: EntityType.Transaction,
            label: "Flashbots Transaction",
            confidence: 1,
          }),
        ],
      }),
    ]);
    expect(mockGetTransactionReceipt).toHaveBeenCalledTimes(2);
  });

  it("should persist the value in a block evenly divisible by 240", async () => {
    const response1 = { data: { blocks: [block1] } };
    const logs1 = [];
    mockGetTransactionReceipt.mockResolvedValueOnce({ logs: logs1 });
    axios.get.mockResolvedValueOnce(response1);
    const mockBlockEvent = {
      blockNumber: 720,
      block: {
        transactions: [],
      },
    };

    await handleBlock(mockBlockEvent);

    expect(mockPersistenceHelper.persist).toHaveBeenCalledTimes(2);
  });

  it("should not persist values because block is not evenly divisible by 240", async () => {
    const response1 = { data: { blocks: [block1] } };
    const logs1 = [];
    mockGetTransactionReceipt.mockResolvedValueOnce({ logs: logs1 });
    axios.get.mockResolvedValueOnce(response1);
    const mockBlockEvent = {
      blockNumber: 600,
      block: {
        transactions: [],
      },
    };

    await handleBlock(mockBlockEvent);

    expect(mockPersistenceHelper.persist).toHaveBeenCalledTimes(0);
  });
});

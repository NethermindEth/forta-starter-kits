const { FindingType, FindingSeverity, Finding, Label, EntityType, createTransactionEvent } = require("forta-agent");
const { provideHandleTranscation, provideHandleBlock, provideInitialize } = require("./agent");

const mockPersistenceHelper = {
  persist: jest.fn(),
  load: jest.fn(),
};

const mockDetectTcFundedAccountContractInteractionsKey =
  "mock-tc-funded-account-bot-detected-contract-interactions-key";
const mockTotalContractInteractionsKey = "mock-tc-funded-account-bot-total-contract-interactions-key";

const mockDetectedTcFundedAccountContractInteractions = 121;
const mockTotalContractInteractions = 8756;

const mockEthersProvider = { getCode: jest.fn(), getNetwork: jest.fn() };

describe("TornadoCash contract interactions", () => {
  let initialize;
  const mockTxEvent = createTransactionEvent({});
  mockTxEvent.filterLog = jest.fn();
  const handleTransaction = provideHandleTranscation(mockEthersProvider);

  beforeEach(async () => {
    mockTxEvent.filterLog.mockReset();
    initialize = provideInitialize(
      mockEthersProvider,
      mockPersistenceHelper,
      mockDetectTcFundedAccountContractInteractionsKey,
      mockTotalContractInteractionsKey
    );
    mockEthersProvider.getNetwork.mockReturnValue({ chainId: 1 });
    mockPersistenceHelper.load
      .mockReturnValueOnce(mockDetectedTcFundedAccountContractInteractions)
      .mockReturnValueOnce(mockTotalContractInteractions);

    await initialize();
  });

  it("returns empty findings if there are no contract interactions with an account that was funded from TornadoCash", async () => {
    mockTxEvent.filterLog.mockReturnValue([]);
    mockTxEvent.transaction = {
      to: "0xb",
    };
    const findings = await handleTransaction(mockTxEvent);

    expect(findings).toStrictEqual([]);

    expect(mockTxEvent.filterLog).toHaveBeenCalledTimes(1);
  });

  it("returns a finding if there is a contract interaction from an address that was funded from TornadoCash", async () => {
    mockTxEvent.filterLog.mockReturnValue([
      {
        args: {
          to: "0xa",
        },
      },
    ]);

    mockTxEvent.transaction = {
      from: "0xa",
      to: "0xb",
      hash: "0xc",
      data: "0x1234567Test",
    };
    mockEthersProvider.getCode.mockReturnValue("0x1234");

    const mockAnomalyScore =
      (mockDetectedTcFundedAccountContractInteractions + 1) / (mockTotalContractInteractions + 1);

    const findings = await handleTransaction(mockTxEvent);

    expect(findings).toStrictEqual([
      Finding.fromObject({
        name: "Tornado Cash funded account interacted with contract",
        description: `${mockTxEvent.transaction.from} interacted with contract ${mockTxEvent.to}`,
        alertId: "TORNADO-CASH-FUNDED-ACCOUNT-INTERACTION",
        severity: FindingSeverity.Low,
        type: FindingType.Suspicious,
        metadata: {
          anomalyScore:
            mockAnomalyScore.toFixed(2) === "0.00" ? mockAnomalyScore.toString() : mockAnomalyScore.toFixed(2),
        },
        labels: [
          Label.fromObject({
            entity: mockTxEvent.transaction.from,
            entityType: EntityType.Address,
            label: "Attacker",
            confidence: 0.7,
          }),
          Label.fromObject({
            entity: mockTxEvent.transaction.hash,
            entityType: EntityType.Transaction,
            label: "Suspicious",
            confidence: 0.7,
          }),
        ],
      }),
    ]);
  });

  it("should not return a finding if the address that was funded from TornadoCash created a contract", async () => {
    mockTxEvent.filterLog.mockReturnValue([
      {
        args: {
          to: "0xa",
        },
      },
    ]);

    mockTxEvent.transaction = {
      from: "0xa",
      to: "", // contract creation
      data: "0x1234567Test",
    };
    const findings = await handleTransaction(mockTxEvent);

    expect(findings).toStrictEqual([]);
  });

  it("should not return a finding if the address that was funded from TornadoCash interacted with a TornadoCash contract", async () => {
    mockTxEvent.filterLog.mockReturnValue([
      {
        args: {
          to: "0xa",
        },
      },
    ]);

    mockTxEvent.transaction = {
      from: "0xa",
      to: "0xbB93e510BbCD0B7beb5A853875f9eC60275CF498", // Ethereum 10 WBTC TC contract
      data: "0x1234567Test",
    };
    mockEthersProvider.getCode.mockReturnValue("0x1234");
    const findings = await handleTransaction(mockTxEvent);

    expect(findings).toStrictEqual([]);
  });
});

describe("Block handler test suite", () => {
  beforeEach(async () => {
    mockEthersProvider.getNetwork.mockReturnValue({ chainId: 1 });

    initialize = provideInitialize(
      mockEthersProvider,
      mockPersistenceHelper,
      mockDetectTcFundedAccountContractInteractionsKey,
      mockTotalContractInteractionsKey
    );
    await initialize();
    handleBlock = provideHandleBlock(
      mockPersistenceHelper,
      mockDetectTcFundedAccountContractInteractionsKey,
      mockTotalContractInteractionsKey
    );
  });

  afterEach(async () => {
    mockPersistenceHelper.persist.mockClear();
  });

  it("should persist the value in a block evenly divisible by 240", async () => {
    const mockBlockEvent = {
      blockNumber: 720,
    };

    await handleBlock(mockBlockEvent);

    expect(mockPersistenceHelper.persist).toHaveBeenCalledTimes(2);
  });

  it("should not persist values because block is not evenly divisible by 240", async () => {
    const mockBlockEvent = {
      blockNumber: 600,
    };

    await handleBlock(mockBlockEvent);

    expect(mockPersistenceHelper.persist).toHaveBeenCalledTimes(0);
  });
});

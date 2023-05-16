const {
  FindingType,
  FindingSeverity,
  Finding,
  Label,
  EntityType,
  createTransactionEvent,
  getEthersProvider,
} = require("forta-agent");
const { provideHandleTranscation, provideInitialize } = require("./agent");
jest.setTimeout(120000);

const mockEthersProvider = { getCode: jest.fn(), getNetwork: jest.fn() };
const mockCalculateRate = jest.fn();

describe("TornadoCash contract interactions", () => {
  let initialize;
  const mockTxEvent = createTransactionEvent({});
  mockTxEvent.filterLog = jest.fn();
  const handleTransaction = provideHandleTranscation(mockEthersProvider, mockCalculateRate);

  beforeEach(async () => {
    mockTxEvent.filterLog.mockReset();
    initialize = provideInitialize(mockEthersProvider);
    mockEthersProvider.getNetwork.mockReturnValue({ chainId: 1 });

    await initialize();
  });

  it("tests performance", async () => {
    const handleRealTransaction = provideHandleTranscation(getEthersProvider(), mockCalculateRate);
    const block = await getEthersProvider().getBlock(1230000);
    console.log(block);
    const normalTxEvent = createTransactionEvent({
      transaction: {
        to: "0x7a250d5630b4cf539739df2c5dacb4c659f2488d", // Uniswap Router
      },
    });

    const contractCreationTxEvent = createTransactionEvent({
      transaction: {
        to: null,
      },
    });

    const TCWithdrawlTxEvent = { filterLog: jest.fn().mockReturnValue([{ args: { to: "0xa" } }]) };

    const contractInteractionTxEvent = {
      filterLog: jest.fn().mockReturnValue([{ args: { to: "0xa" } }]),
      transaction: { from: "0xa", to: "0xb", hash: "0xc", data: "0x1234567Test" },
      to: "0x7a250d5630b4cf539739df2c5dacb4c659f2488d", // Uniswap Router
      from: "0xa",
    };
    mockCalculateRate.mockReturnValue(0.01);

    //     Chain: Blocktime, Number of Tx -> Avg processing time in ms target
    //     Ethereum: 12s, 150 -> 80ms
    //     BSC: 3s, 70 -> 43ms
    //     Polygon: 2s, 50 -> 40ms
    //     Arbitrum: 1s, 5 -> 200ms
    //     Optimism: 24s, 150 -> 160ms

    //      local testing reveals an avg processing time of 125, which results in the following sharding config:
    //      Ethereum: 12s, 150 -> 80ms - 2
    //      BSC: 3s, 70 -> 43ms - 3
    //      Polygon: 2s, 50 -> 40ms - 4
    //      Arbitrum: 1s, 5 -> 200ms - 1
    //      Optimism: 24s, 150 -> 160ms - 1

    const processingRuns = 20;
    let totalTimeNormalFunding = 0;
    let totalTimeContractCreationFunding = 0;
    let totalTimeTcFunding = 0;
    let totalTimeContractInteractionFunding = 0;
    for (let i = 0; i < processingRuns; i++) {
      const startTimeNormalFunding = performance.now();
      await handleRealTransaction(normalTxEvent);
      const endTimeNormalFunding = performance.now();
      totalTimeNormalFunding += endTimeNormalFunding - startTimeNormalFunding;

      const startTimeContractCreationFunding = performance.now();
      await handleRealTransaction(contractCreationTxEvent);
      const endTimeContractCreationFunding = performance.now();
      totalTimeContractCreationFunding += endTimeContractCreationFunding - startTimeContractCreationFunding;

      const startTimeTcFunding = performance.now();
      await handleRealTransaction(TCWithdrawlTxEvent);
      const endTimeTcFunding = performance.now();
      totalTimeTcFunding += endTimeTcFunding - startTimeTcFunding;

      const startTimeContractInteractionFunding = performance.now();
      await handleRealTransaction(contractInteractionTxEvent);
      const endTimeContractInteractionFunding = performance.now();
      totalTimeContractInteractionFunding += endTimeContractInteractionFunding - startTimeContractInteractionFunding;
    }
    const processingTimeNormalFundingAvgMs = totalTimeNormalFunding / processingRuns;
    const processingTimeContractCreationFundingAvgMs = totalTimeContractCreationFunding / processingRuns;
    const processingTimeTcFundingAvgMs = totalTimeTcFunding / processingRuns;
    const processingTimeContractInteractionFundingAvgMs = totalTimeContractInteractionFunding / processingRuns;

    expect(
      (processingTimeNormalFundingAvgMs * 0.984 +
        processingTimeContractCreationFundingAvgMs * 0.01 +
        processingTimeTcFundingAvgMs * 0.001 +
        processingTimeContractInteractionFundingAvgMs * 0.005) /
        4
    ).toBeLessThan(125);
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

    mockCalculateRate.mockResolvedValueOnce(0.032);

    const findings = await handleTransaction(mockTxEvent);

    expect(findings).toStrictEqual([
      Finding.fromObject({
        name: "Tornado Cash funded account interacted with contract",
        description: `${mockTxEvent.transaction.from} interacted with contract ${mockTxEvent.to}`,
        alertId: "TORNADO-CASH-FUNDED-ACCOUNT-INTERACTION",
        severity: FindingSeverity.Low,
        type: FindingType.Suspicious,
        metadata: {
          anomalyScore: "0.032",
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

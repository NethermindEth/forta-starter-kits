const { Finding, FindingSeverity, FindingType } = require("forta-agent");
const { persistenceHelper } = require("./persistence.helper");
const {
  provideHandleTransaction,
  provideHandleBlock,
  resetIsFirstBlock,
  resetIsTrained,
  initialize,
} = require("./agent");
const ARIMA = require("arima");
const ARIMA_SETTINGS = {
  p: 2,
  d: 1,
  q: 2,
  P: 1,
  D: 0,
  Q: 1,
  s: 5,
  verbose: false,
};
jest.mock("./agent.config.js", () => {
  const actualModule = jest.requireActual("./agent.config.js");
  return {
    ...actualModule,
    bucketBlockSize: 0,
  };
});


describe("Transaction Volume Anomaly Detection", () => {
  const mockTxEvent = {
    to: "0x123",
    hash: "0x0",
    traces: [],
  };

  const mockTxEventWithTraces = {
    to: "0x123",
    traces: [
      {
        action: {
          to: "0x123",
        },
        error: false,
      },
    ],
  };

  const mockBlockEvent = {
    block: {
      timestamp: 1,
    },
    blockNumber: 70,
  };

  const mockPersistenceHelper = {
    persist: jest.fn(),
    load: jest.fn(),
  };

  const mockGetTxReceipt = jest.fn();
  let mockTracker;
  let mockContracts = ["0x123"];
  let handleTransaction;
  let handleBlock;
  beforeEach(() => {
    initialize(mockPersistenceHelper);
    mockBlockEvent.block.timestamp = 1;
    mockTxEventWithTraces.traces[0].error = false;
    mockGetTxReceipt.mockReset();
    mockTracker = {
      "0x123": {
        successfulTx: {
          TSA: new ARIMA(ARIMA_SETTINGS),
          txTracker: [],
          txCount: 0,
          currentBlockCount: 0,
        },
        failedTx: {
          TSA: new ARIMA(ARIMA_SETTINGS),
          txTracker: [],
          txCount: 0,
          currentBlockCount: 0,
        },
        successfulInternalTx: {
          TSA: new ARIMA(ARIMA_SETTINGS),
          txTracker: [],
          txCount: 0,
          currentBlockCount: 0,
        },
        failedInternalTx: {
          TSA: new ARIMA(ARIMA_SETTINGS),
          txTracker: [],
          txCount: 0,
          currentBlockCount: 0,
        },
      },
    };
    handleTransaction = provideHandleTransaction(
      mockTracker,
      mockContracts,
      mockGetTxReceipt
    );
    handleBlock = provideHandleBlock(mockTracker, mockContracts);
    resetIsFirstBlock();
    resetIsTrained();
  });

  it("Should successfully increment on successful transaction", async () => {
    mockGetTxReceipt.mockReturnValue({ status: true });
    await handleTransaction(mockTxEvent);

    expect(mockTracker["0x123"].successfulTx.txCount).toBe(1);
  });

  it("Should successfully increment on failed transaction", async () => {
    mockGetTxReceipt.mockReturnValue({ status: false });
    await handleTransaction(mockTxEvent);

    expect(mockTracker["0x123"].failedTx.txCount).toBe(1);
  });

  it("Should successfully increment on successful internal transaction", async () => {
    mockGetTxReceipt.mockReturnValue({ status: true });
    await handleTransaction(mockTxEventWithTraces);

    expect(mockTracker["0x123"].successfulInternalTx.txCount).toBe(1);
  });

  it("Should successfully increment on failed internal transaction", async () => {
    mockGetTxReceipt.mockReturnValue({ status: false });
    mockTxEventWithTraces.traces[0].error = true;
    await handleTransaction(mockTxEventWithTraces);

    expect(mockTracker["0x123"].failedInternalTx.txCount).toBe(1);
  });

  it("Should successfully push to txTracker array in successful transactions", async () => {
    mockGetTxReceipt.mockReturnValue({ status: true });

    await handleTransaction(mockTxEvent);
    await handleBlock(mockBlockEvent);
    mockBlockEvent.block.timestamp = 5;
    await handleBlock(mockBlockEvent);
    expect(mockTracker["0x123"].successfulTx.txTracker).toStrictEqual([1]);
  });

  it("Should successfully push to txTracker array in failed transactions", async () => {
    mockGetTxReceipt.mockReturnValue({ status: false });

    await handleTransaction(mockTxEvent);
    await handleBlock(mockBlockEvent);
    mockBlockEvent.block.timestamp = 5;
    await handleBlock(mockBlockEvent);
    expect(mockTracker["0x123"].failedTx.txTracker).toStrictEqual([1]);
  });

  it("Should successfully push to txTracker array in successful internal transactions", async () => {
    mockGetTxReceipt.mockReturnValue({ status: true });
    await handleTransaction(mockTxEventWithTraces);
    await handleBlock(mockBlockEvent);
    mockBlockEvent.block.timestamp = 5;
    await handleBlock(mockBlockEvent);
    expect(mockTracker["0x123"].successfulInternalTx.txTracker).toStrictEqual([
      1,
    ]);
  });

  it("Should successfully push to txTracker array in failed internal transactions", async () => {
    mockGetTxReceipt.mockReturnValue({ status: false });
    mockTxEventWithTraces.traces[0].error = true;

    await handleTransaction(mockTxEventWithTraces);
    await handleBlock(mockBlockEvent);
    mockBlockEvent.block.timestamp = 5;
    await handleBlock(mockBlockEvent);
    expect(mockTracker["0x123"].failedInternalTx.txTracker).toStrictEqual([1]);
  });

  it("Should successfully train model if timestamp threshold passes for successful transaction", async () => {
    mockGetTxReceipt.mockReturnValue({ status: true });

    await handleTransaction(mockTxEvent);
    await handleBlock(mockBlockEvent);
    mockBlockEvent.block.timestamp = 1;
    await handleBlock(mockBlockEvent);
    expect(mockTracker["0x123"].successfulTx.txTracker).toStrictEqual([1]);
  });

  it("Should successfully train model if timestamp threshold passes for failed transaction", async () => {
    mockGetTxReceipt.mockReturnValue({ status: false });

    await handleTransaction(mockTxEvent);
    mockBlockEvent.block.timestamp = 1;
    await handleBlock(mockBlockEvent);
    await handleBlock(mockBlockEvent);
    expect(mockTracker["0x123"].failedTx.txTracker).toStrictEqual([1]);
  });

  it("Should successfully train model if timestamp threshold passes for successful internal transaction", async () => {
    mockGetTxReceipt.mockReturnValue({ status: true });
    await handleTransaction(mockTxEventWithTraces);
    await handleBlock(mockBlockEvent);
    mockBlockEvent.block.timestamp = 1;
    await handleBlock(mockBlockEvent);
    expect(mockTracker["0x123"].successfulInternalTx.txTracker).toStrictEqual([
      1,
    ]);
  });

  it("Should successfully train model if timestamp threshold passes for failed internal transaction", async () => {
    mockGetTxReceipt.mockReturnValue({ status: false });
    mockTxEventWithTraces.traces[0].error = true;
    await handleTransaction(mockTxEventWithTraces);
    await handleBlock(mockBlockEvent);
    mockBlockEvent.block.timestamp = 1;
    await handleBlock(mockBlockEvent);
    expect(mockTracker["0x123"].failedInternalTx.txTracker).toStrictEqual([1]);
  });

  it("Should return no findings if there are no transaction volume anomalies for successful transactions", async () => {
    mockGetTxReceipt.mockReturnValue({ status: true });
    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 10; i++) {
      await handleTransaction(mockTxEvent);
    }
    mockBlockEvent.block.timestamp = 5;
    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 15; i++) {
      await handleTransaction(mockTxEvent);
    }
    mockBlockEvent.block.timestamp = 1;
    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 10; i++) {
      await handleTransaction(mockTxEvent);
    }

    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 16; i++) {
      await handleTransaction(mockTxEvent);
    }

    const findings = await handleBlock(mockBlockEvent);

    expect(findings).toStrictEqual([]);
  });

  it("Should return no findings if there are no transaction volume anomalies for failed transactions", async () => {
    mockGetTxReceipt.mockReturnValue({ status: false });
    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 10; i++) {
      await handleTransaction(mockTxEvent);
    }
    mockBlockEvent.block.timestamp = 5;
    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 15; i++) {
      await handleTransaction(mockTxEvent);
    }

    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 10; i++) {
      await handleTransaction(mockTxEvent);
    }

    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 10; i++) {
      await handleTransaction(mockTxEvent);
    }

    mockBlockEvent.block.timestamp = 1;
    const findings = await handleBlock(mockBlockEvent);

    expect(findings).toStrictEqual([]);
  });

  it("Should return no findings if there are no transaction volume anomalies for successful internal transactions", async () => {
    mockGetTxReceipt.mockReturnValue({ status: true });
    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 10; i++) {
      await handleTransaction(mockTxEventWithTraces);
    }
    mockBlockEvent.block.timestamp = 5;
    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 15; i++) {
      await handleTransaction(mockTxEventWithTraces);
    }

    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 10; i++) {
      await handleTransaction(mockTxEventWithTraces);
    }

    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 10; i++) {
      await handleTransaction(mockTxEventWithTraces);
    }

    mockBlockEvent.block.timestamp = 1;
    const findings = await handleBlock(mockBlockEvent);

    expect(findings).toStrictEqual([]);
  });

  it("Should return no findings if there are no transaction volume anomalies for failed internal transactions", async () => {
    mockGetTxReceipt.mockReturnValue({ status: false });
    mockTxEventWithTraces.traces[0].error = true;
    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 10; i++) {
      await handleTransaction(mockTxEventWithTraces);
    }
    mockBlockEvent.block.timestamp = 5;
    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 15; i++) {
      await handleTransaction(mockTxEventWithTraces);
    }

    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 10; i++) {
      await handleTransaction(mockTxEventWithTraces);
    }

    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 10; i++) {
      await handleTransaction(mockTxEventWithTraces);
    }

    mockBlockEvent.block.timestamp = 1;
    const findings = await handleBlock(mockBlockEvent);

    expect(findings).toStrictEqual([]);
  });

  it("Should return findings if there are transaction volume anomalies for successful transactions", async () => {
    mockGetTxReceipt.mockReturnValue({ status: true });
    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 10; i++) {
      await handleTransaction(mockTxEvent);
    }
    mockBlockEvent.block.timestamp = 5;
    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 15; i++) {
      await handleTransaction(mockTxEvent);
    }

    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 10; i++) {
      await handleTransaction(mockTxEvent);
    }
    mockBlockEvent.block.timestamp = 1;
    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 1600; i++) {
      await handleTransaction(mockTxEvent);
    }

    const findings = await handleBlock(mockBlockEvent);

    expect(findings).toStrictEqual([
      Finding.fromObject({
        name: "Unusually high number of successful transactions",
        description: `Significant increase of successful transactions have been observed from 70 to 70`,
        alertId: "SUCCESSFUL-TRANSACTION-VOL-INCREASE",
        severity: FindingSeverity.Low,
        type: FindingType.Suspicious,
        metadata: {
          COUNT: 1600,
          EXPECTED_BASELINE: 10,
        },
      }),
    ]);
  });

  it("Should return findings if there are transaction volume anomalies for failed transactions", async () => {
    mockGetTxReceipt.mockReturnValue({ status: false });
    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 10; i++) {
      await handleTransaction(mockTxEvent);
    }

    mockBlockEvent.block.timestamp = 5;
    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 15; i++) {
      await handleTransaction(mockTxEvent);
    }

    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 10; i++) {
      await handleTransaction(mockTxEvent);
    }
    mockBlockEvent.block.timestamp = 1;
    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 1600; i++) {
      await handleTransaction(mockTxEvent);
    }

    const findings = await handleBlock(mockBlockEvent);

    expect(findings).toStrictEqual([
      Finding.fromObject({
        name: "Unusually high number of failed transactions",
        description: `Significant increase of failed transactions have been observed from  70 to 70`,
        alertId: "FAILED-TRANSACTION-VOL-INCREASE",
        severity: FindingSeverity.High,
        type: FindingType.Exploit,
        metadata: {
          COUNT: 1600,
          EXPECTED_BASELINE: 10,
        },
      }),
    ]);
  });

  it("Should return findings if there are transaction volume anomalies for successful internal transactions", async () => {
    mockGetTxReceipt.mockReturnValue({ status: true });

    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 10; i++) {
      await handleTransaction(mockTxEventWithTraces);
    }
    mockBlockEvent.block.timestamp = 5;
    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 15; i++) {
      await handleTransaction(mockTxEventWithTraces);
    }
    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 10; i++) {
      await handleTransaction(mockTxEventWithTraces);
    }
    mockBlockEvent.block.timestamp = 1;
    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 1600; i++) {
      await handleTransaction(mockTxEventWithTraces);
    }

    const findings = await handleBlock(mockBlockEvent);

    expect(findings).toStrictEqual([
      Finding.fromObject({
        name: "Unusually high number of successful transactions",
        description: `Significant increase of successful transactions have been observed from 70 to 70`,
        alertId: "SUCCESSFUL-TRANSACTION-VOL-INCREASE",
        severity: FindingSeverity.Low,
        type: FindingType.Suspicious,
        metadata: {
          COUNT: 1600,
          EXPECTED_BASELINE: 10,
        },
      }),
      Finding.fromObject({
        name: "Unusually high number of successful internal transactions",
        description: `Significant increase of successful internal transactions have been observed from 70 to 70`,
        alertId: "SUCCESSFUL-INTERNAL-TRANSACTION-VOL-INCREASE",
        severity: FindingSeverity.Low,
        type: FindingType.Suspicious,
        metadata: {
          COUNT: 1600,
          EXPECTED_BASELINE: 10,
        },
      }),
    ]);
  });

  it("Should return findings if there are transaction volume anomalies for failed internal transactions", async () => {
    mockGetTxReceipt.mockReturnValue({ status: false });
    mockTxEventWithTraces.traces[0].error = true;
    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 10; i++) {
      await handleTransaction(mockTxEventWithTraces);
    }

    mockBlockEvent.block.timestamp = 5;
    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 15; i++) {
      await handleTransaction(mockTxEventWithTraces);
    }
    mockBlockEvent.block.timestamp = 1;
    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 10; i++) {
      await handleTransaction(mockTxEventWithTraces);
    }

    await handleBlock(mockBlockEvent);
    for (let i = 0; i < 1600; i++) {
      await handleTransaction(mockTxEventWithTraces);
    }

    const findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual([
      Finding.fromObject({
        name: "Unusually high number of failed transactions",
        description: `Significant increase of failed transactions have been observed from  70 to 70`,
        alertId: "FAILED-TRANSACTION-VOL-INCREASE",
        severity: FindingSeverity.High,
        type: FindingType.Exploit,
        metadata: {
          COUNT: 1600,
          EXPECTED_BASELINE: 10,
        },
      }),
      Finding.fromObject({
        name: "Unusually high number of failed internal transactions",
        description: `Significant increase of failed internal transactions have been observed from 70 to 70`,
        alertId: "FAILED-INTERNAL-TRANSACTION-VOL-INCREASE",
        severity: FindingSeverity.Medium,
        type: FindingType.Suspicious,
        metadata: {
          COUNT: 1600,
          EXPECTED_BASELINE: 10,
        },
      }),
    ]);
  });
});

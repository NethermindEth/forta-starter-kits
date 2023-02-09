const { FindingType, FindingSeverity, Finding, ethers, getEthersProvider, Label, EntityType } = require("forta-agent");
const {
  handleTransaction,
  provideInitialize,
  provideHandleBlock,
  getContractAssets,
  resetLastTimestamp,
} = require("./agent");

const contractAddress = "0xcontract";
const asset = "0xasset";
const txHash = "hash";

// Mock the config file
jest.mock(
  "../bot-config.json",
  () => ({
    aggregationTimePeriod: 100,
    contractAddress,
  }),
  { virtual: true }
);

const mockBalanceOf = jest.fn();

// Mock the balanceOf method
jest.mock("forta-agent", () => {
  const original = jest.requireActual("forta-agent");
  return {
    ...original,
    getEthersProvider: jest.fn(),
    ethers: {
      ...original.ethers,
      Contract: jest.fn().mockImplementation(() => ({
        balanceOf: mockBalanceOf,
        decimals: () => 18,
      })),
    },
  };
});

const mockGetBalance = jest.fn();
getEthersProvider.mockImplementation(() => ({ getBalance: mockGetBalance, _isSigner: true }));

function resetState() {
  const contractAssets = getContractAssets();
  Object.keys(contractAssets).forEach((k) => delete contractAssets[k]);
  resetLastTimestamp();
}

const mockAllRemovedKey = "mock-all-removed-key";
const mockPortionRemovedKey = "mock-portion-removed-key";
const mockAllTransfersKey = "mock-all-transfers-bot-key";

const allRemovedTransfers = 6;
const portionRemovedTransfers = 9;
const totalTransferTransactions = 3300000;

describe("large balance decrease bot", () => {
  const mockProvider = {
    getNetwork: jest.fn(),
  };
  const mockPersistenceHelper = {
    persist: jest.fn(),
    load: jest.fn(),
  };

  let initialize;
  let handleBlock;
  describe("handleTransaction", () => {
    const mockTxEvent = {
      blockNumber: 1000,
      from: "0x01",
      hash: txHash,
      filterLog: jest.fn(),
      traces: [],
    };

    beforeEach(async () => {
      resetState();
      mockTxEvent.filterLog.mockReset();
      mockBalanceOf.mockReset();
      mockGetBalance.mockReset();

      mockProvider.getNetwork.mockReturnValueOnce({ chainId: 1 });

      initialize = provideInitialize(
        mockProvider,
        mockPersistenceHelper,
        mockAllRemovedKey,
        mockPortionRemovedKey,
        mockAllTransfersKey
      );

      mockPersistenceHelper.load
        .mockReturnValueOnce(allRemovedTransfers)
        .mockReturnValueOnce(portionRemovedTransfers)
        .mockReturnValueOnce(totalTransferTransactions);

      await initialize();
    });

    it("should return empty findings if there are no Transfer events", async () => {
      mockTxEvent.filterLog.mockReturnValueOnce([]);
      mockGetBalance.mockResolvedValueOnce(ethers.BigNumber.from(100));

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([]);
      expect(mockTxEvent.filterLog).toHaveBeenCalledTimes(1);
    });

    it("should return empty findings if there are no Transfer to or from the contract address", async () => {
      const event = { args: { from: "0xfrom", to: "0xto" } };
      mockTxEvent.filterLog.mockReturnValueOnce([event]);
      mockGetBalance.mockResolvedValueOnce(ethers.BigNumber.from(100));

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([]);
      expect(mockTxEvent.filterLog).toHaveBeenCalledTimes(1);
    });

    it("should set the balance if there is a transfer of new asset", async () => {
      const event = {
        address: asset,
        args: {
          from: "0xfrom",
          to: contractAddress,
          value: ethers.BigNumber.from(50),
        },
      };
      mockBalanceOf.mockResolvedValueOnce(ethers.BigNumber.from(100));
      mockGetBalance.mockResolvedValueOnce(ethers.BigNumber.from(100));
      mockTxEvent.filterLog.mockReturnValueOnce([event]);

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([]);
      expect(mockTxEvent.filterLog).toHaveBeenCalledTimes(1);
      expect(mockBalanceOf).toHaveBeenCalledTimes(1);
    });

    it("should return empty findings if the balance is not drained", async () => {
      const event = {
        address: asset,
        args: {
          from: contractAddress,
          to: "0xto",
          value: ethers.BigNumber.from(50),
        },
      };
      mockBalanceOf.mockResolvedValueOnce(ethers.BigNumber.from(100));
      mockGetBalance.mockResolvedValueOnce(ethers.BigNumber.from(100));
      mockTxEvent.filterLog.mockReturnValueOnce([event]);

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([]);
      expect(mockTxEvent.filterLog).toHaveBeenCalledTimes(1);
      expect(mockBalanceOf).toHaveBeenCalledTimes(1);
    });

    it("should return findings if the balance is drained", async () => {
      const event = {
        address: asset,
        args: {
          from: contractAddress,
          to: "0xto",
          value: ethers.BigNumber.from(100),
        },
      };
      mockBalanceOf.mockResolvedValueOnce(ethers.BigNumber.from(100));
      mockGetBalance.mockResolvedValueOnce(ethers.BigNumber.from(100));
      mockTxEvent.filterLog.mockReturnValueOnce([event]);

      const mockAnomalyScore = (allRemovedTransfers + 1) / (totalTransferTransactions + 1);

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Assets removed",
          description: `All ${asset} tokens have been removed from ${contractAddress}.`,
          alertId: "BALANCE-DECREASE-ASSETS-ALL-REMOVED",
          severity: FindingSeverity.Critical,
          type: FindingType.Exploit,
          metadata: {
            firstTxHash: txHash,
            lastTxHash: txHash,
            assetImpacted: asset,
            anomalyScore:
              mockAnomalyScore.toFixed(2) === "0.00" ? mockAnomalyScore.toString() : mockAnomalyScore.toFixed(2),
          },
          labels: [
            Label.fromObject({
              entityType: EntityType.Transaction,
              entity: txHash,
              label: "Suspicious",
              confidence: 0.9,
            }),
            Label.fromObject({
              entityType: EntityType.Transaction,
              entity: txHash,
              label: "Suspicious",
              confidence: 0.9,
            }),
            Label.fromObject({
              entityType: EntityType.Address,
              entity: contractAddress,
              label: "Victim",
              confidence: 0.9,
            }),
            Label.fromObject({
              entityType: EntityType.Address,
              entity: "0x01",
              label: "Attacker",
              confidence: 0.9,
            }),
            Label.fromObject({
              entityType: EntityType.Address,
              entity: "0x01",
              label: "Attacker",
              confidence: 0.9,
            }),
          ],
        }),
      ]);
      expect(mockTxEvent.filterLog).toHaveBeenCalledTimes(1);
      expect(mockBalanceOf).toHaveBeenCalledTimes(1);
    });

    it("should return findings if the native balance is drained", async () => {
      mockGetBalance.mockResolvedValueOnce(ethers.BigNumber.from(100));
      mockTxEvent.traces.push({
        action: {
          callType: "call",
          from: contractAddress,
          to: "0x812c0b2a2a0a74f6f6ed620fbd2b67fec7db2190",
          value: "0x64",
        },
      });
      mockTxEvent.filterLog.mockReturnValueOnce([]);

      const mockAnomalyScore = (allRemovedTransfers + 1) / (totalTransferTransactions + 1);

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Assets removed",
          description: `All native tokens have been removed from ${contractAddress}.`,
          alertId: "BALANCE-DECREASE-ASSETS-ALL-REMOVED",
          severity: FindingSeverity.Critical,
          type: FindingType.Exploit,
          metadata: {
            firstTxHash: txHash,
            lastTxHash: txHash,
            assetImpacted: "native",
            anomalyScore:
              mockAnomalyScore.toFixed(2) === "0.00" ? mockAnomalyScore.toString() : mockAnomalyScore.toFixed(2),
          },
          labels: [
            Label.fromObject({
              entityType: EntityType.Transaction,
              entity: txHash,
              label: "Suspicious",
              confidence: 0.9,
            }),
            Label.fromObject({
              entityType: EntityType.Transaction,
              entity: txHash,
              label: "Suspicious",
              confidence: 0.9,
            }),
            Label.fromObject({
              entityType: EntityType.Address,
              entity: contractAddress,
              label: "Victim",
              confidence: 0.9,
            }),
            Label.fromObject({
              entityType: EntityType.Address,
              entity: "0x01",
              label: "Attacker",
              confidence: 0.9,
            }),
            Label.fromObject({
              entityType: EntityType.Address,
              entity: "0x01",
              label: "Attacker",
              confidence: 0.9,
            }),
          ],
        }),
      ]);
      expect(mockTxEvent.filterLog).toHaveBeenCalledTimes(1);
    });
  });

  // handle block
  describe("handleBlock", () => {
    beforeEach(async () => {
      resetState();
      mockBalanceOf.mockReset();

      mockProvider.getNetwork.mockReturnValueOnce({ chainId: 1 });

      initialize = provideInitialize(
        mockProvider,
        mockPersistenceHelper,
        mockAllRemovedKey,
        mockPortionRemovedKey,
        mockAllTransfersKey
      );

      mockPersistenceHelper.load
        .mockReturnValueOnce(allRemovedTransfers)
        .mockReturnValueOnce(portionRemovedTransfers)
        .mockReturnValueOnce(totalTransferTransactions);

      await initialize();

      handleBlock = provideHandleBlock(
        mockPersistenceHelper,
        mockAllRemovedKey,
        mockPortionRemovedKey,
        mockAllTransfersKey
      );
    });

    it("should return empty findings if not enough time has passed", async () => {
      const mockBlockEvent = { block: { timestamp: 10 } };

      const findings = await handleBlock(mockBlockEvent);
      expect(findings).toStrictEqual([]);
    });

    it("should return empty findings if there is not enough data", async () => {
      getContractAssets()[asset] = {
        balance: ethers.BigNumber.from(100),
        timeSeries: [10, 10, 10],
      };

      const mockBlockEvent = { block: { timestamp: 1000 } };
      const findings = await handleBlock(mockBlockEvent);
      expect(findings).toStrictEqual([]);

      // Reset the contractAssets
      delete getContractAssets()[asset];
    });

    it("should return finding if there is an anomaly", async () => {
      // Create transaction that contains a withdraw of 100 tokens
      const mockTxEvent = {
        blockNumber: 1000,
        from: "0x1",
        hash: txHash,
        filterLog: jest.fn(),
        traces: [],
      };
      const event = {
        address: asset,
        args: {
          from: contractAddress,
          to: "0xto",
          value: ethers.utils.parseEther("100"),
        },
      };

      // The tx withdraws 100 and the remaining balance is 1000 (10%)
      mockBalanceOf.mockResolvedValueOnce(ethers.utils.parseEther("1100"));

      mockTxEvent.filterLog.mockReturnValueOnce([event]);
      await handleTransaction(mockTxEvent);

      // Create time series with 11 elements of value 10 and set the bal
      const timeSeries = Array(11)
        .fill()
        .map(() => 10);
      getContractAssets()[asset].timeSeries = timeSeries;

      // Handle the block
      const mockBlockEvent = { block: { timestamp: 1000 } };
      const mockAnomalyScore = (portionRemovedTransfers + 1) / (totalTransferTransactions + 1);

      const findings = await handleBlock(mockBlockEvent);
      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Assets significantly decreased",
          description: `A significant amount ${asset} tokens have been removed from ${contractAddress}.`,
          alertId: "BALANCE-DECREASE-ASSETS-PORTION-REMOVED",
          severity: FindingSeverity.Medium,
          type: FindingType.Exploit,
          metadata: {
            firstTxHash: txHash,
            lastTxHash: txHash,
            assetImpacted: asset,
            assetVolumeDecreasePercentage: 1000 / 100,
            anomalyScore:
              mockAnomalyScore.toFixed(2) === "0.00" ? mockAnomalyScore.toString() : mockAnomalyScore.toFixed(2),
          },
          labels: [
            Label.fromObject({
              entityType: EntityType.Transaction,
              entity: txHash,
              label: "Suspicious",
              confidence: 0.7,
            }),
            Label.fromObject({
              entityType: EntityType.Transaction,
              entity: txHash,
              label: "Suspicious",
              confidence: 0.7,
            }),
            Label.fromObject({
              entityType: EntityType.Address,
              entity: contractAddress,
              label: "Victim",
              confidence: 0.7,
            }),
            Label.fromObject({
              entityType: EntityType.Address,
              entity: "0x1",
              label: "Attacker",
              confidence: 0.7,
            }),
            Label.fromObject({
              entityType: EntityType.Address,
              entity: "0x1",
              label: "Attacker",
              confidence: 0.7,
            }),
          ],
        }),
      ]);

      // Reset the contractAssets
      delete getContractAssets()[asset];
    });
  });

  describe("Persistence functionality", () => {
    afterEach(() => {
      mockPersistenceHelper.persist.mockClear();
    });

    it("should persist the value in a block evenly divisible by 240", async () => {
      const mockBlockEvent = {
        block: {
          number: 720,
        },
      };

      await handleBlock(mockBlockEvent);

      expect(mockPersistenceHelper.persist).toHaveBeenCalledTimes(3);
    });

    it("should not persist values because block is not evenly divisible by 240", async () => {
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

const mockEthcallProviderTryAll = jest.fn();
const mockBalanceOf = jest.fn();

const { FindingType, FindingSeverity, Finding, ethers, Label, EntityType } = require("forta-agent");
const { createAddress } = require("forta-agent-tools");
const { provideInitialize, provideHandleTransaction, provideHandleBlock, getTransfersObj } = require("./agent");

function hashCode(address, asset) {
  const str = address + asset;
  let hash = 0;
  if (str.length === 0) return hash;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash &= hash; // Convert to 32bit integer
  }
  return hash;
}

const mockAssetDrainedTxnKey = "mock-asset-drained-bot-key";
const mockAllTransfersKey = "mock-all-transfers-bot-key";

const assetDrainedTransactions = 6;
const totalTransferTransactions = 33;

const asset = createAddress("0x01");
const address1 = createAddress("0x02");
const address2 = createAddress("0x03");
const address3 = createAddress("0x04");
const address4 = createAddress("0x05");
const address5 = createAddress("0x06");

const hashCode1 = hashCode(address1, asset);
const hashCode2 = hashCode(address2, asset);
const hashCode3 = hashCode(address3, asset);

const symbol = "TOKEN";

jest.mock("forta-agent-tools", () => {
  const original = jest.requireActual("forta-agent-tools");
  return {
    ...original,
    MulticallProvider: jest.fn().mockImplementation(() => ({
      tryAll: mockEthcallProviderTryAll,
      init: jest.fn(),
    })),
  };
});

jest.mock("forta-agent", () => {
  const original = jest.requireActual("forta-agent");
  return {
    ...original,
    getEthersProvider: jest.fn().mockImplementation(() => ({
      _isSigner: true,
      getCode: () => "0x000000",
    })),
    ethers: {
      ...original.ethers,
      Contract: jest.fn().mockImplementation(() => ({
        balanceOf: mockBalanceOf,
        symbol: () => symbol,
      })),
    },
  };
});

describe("Asset drained bot test suite", () => {
  describe("handleTransaction", () => {
    const mockTxEvent = {
      filterLog: jest.fn(),
      blockNumber: 9999,
      hash: ethers.utils.formatBytes32String("0x352352"),
      from: address4,
      traces: [],
    };

    let handleTransaction;

    beforeEach(() => {
      handleTransaction = provideHandleTransaction();
      mockTxEvent.filterLog.mockReset();
      Object.keys(getTransfersObj()).forEach((key) => delete getTransfersObj()[key]);
    });

    it("should do nothing if there are no transfers", async () => {
      mockTxEvent.filterLog.mockReturnValueOnce([]);
      await handleTransaction(mockTxEvent);
      expect(Object.keys(getTransfersObj()).length).toStrictEqual(0);
    });

    it("should add transfers in the object if there are transfers", async () => {
      const mockTransferEvent1 = {
        address: asset,
        args: {
          from: address1,
          to: address2,
          value: ethers.BigNumber.from(10),
        },
      };
      const mockTransferEvent2 = {
        address: asset,
        args: {
          from: address2,
          to: address3,
          value: ethers.BigNumber.from(10),
        },
      };
      mockTxEvent.filterLog.mockReturnValueOnce([mockTransferEvent1, mockTransferEvent2]);

      await handleTransaction(mockTxEvent);
      expect(Object.keys(getTransfersObj()).length).toStrictEqual(3);
      expect(getTransfersObj()[hashCode1]).toStrictEqual({
        asset,
        address: address1,
        value: ethers.BigNumber.from(-10),
        blockNumber: 9999,
        txs: {
          "0x0000000000000000000000000000000000000003": [
            { hash: ethers.utils.formatBytes32String("0x352352"), txFrom: address4 },
          ],
        },
      });
      expect(getTransfersObj()[hashCode2]).toStrictEqual({
        asset,
        address: address2,
        value: ethers.BigNumber.from(0),
        blockNumber: 9999,
        txs: {
          "0x0000000000000000000000000000000000000004": [
            { hash: ethers.utils.formatBytes32String("0x352352"), txFrom: address4 },
          ],
        },
      });
      expect(getTransfersObj()[hashCode3]).toStrictEqual({
        asset,
        address: address3,
        value: ethers.BigNumber.from(10),
        blockNumber: 9999,
        txs: {},
      });
    });
  });

  describe("handleBlock", () => {
    const mockProvider = {
      getNetwork: jest.fn(),
    };
    const mockPersistenceHelper = {
      persist: jest.fn(),
      load: jest.fn(),
    };

    let initialize;
    let handleTransaction;
    let handleBlock;

    const mockTxEvent = {
      filterLog: jest.fn(),
      blockNumber: 9999,
      hash: ethers.utils.formatBytes32String("0x2352352"),
      from: address4,
      traces: [],
    };
    const mockTxEvent2 = {
      filterLog: jest.fn(),
      blockNumber: 9999,
      hash: ethers.utils.formatBytes32String("0x442352352"),
      from: address5,
      traces: [],
    };

    beforeEach(async () => {
      mockProvider.getNetwork.mockReturnValueOnce({ chainId: 1 });

      initialize = provideInitialize(mockProvider, mockPersistenceHelper, mockAssetDrainedTxnKey, mockAllTransfersKey);

      mockPersistenceHelper.load
        .mockReturnValueOnce(assetDrainedTransactions)
        .mockReturnValueOnce(totalTransferTransactions);

      await initialize();

      handleTransaction = provideHandleTransaction();

      handleBlock = provideHandleBlock(mockPersistenceHelper, mockAssetDrainedTxnKey, mockAssetDrainedTxnKey);

      mockTxEvent.filterLog.mockReset();
      mockTxEvent2.filterLog.mockReset();
      mockEthcallProviderTryAll.mockReset();
      Object.keys(getTransfersObj()).forEach((key) => delete getTransfersObj()[key]);
    });

    describe("Alert Generation", () => {
      const mockBlockEvent = { blockNumber: 10_000 };

      it("should not alert if there are no transfers", async () => {
        mockTxEvent.filterLog.mockReturnValueOnce([]);
        await handleTransaction(mockTxEvent);
        const findings = await handleBlock(mockBlockEvent);
        expect(findings).toStrictEqual([]);
      });

      it("should alert if there are contracts that had 99% or more of their assets drained", async () => {
        const mockTransferEvent1 = {
          address: asset,
          args: {
            from: address1,
            to: address2,
            value: ethers.BigNumber.from(995),
          },
        };
        mockTxEvent.filterLog.mockReturnValueOnce([mockTransferEvent1]);
        // Balance call for pre-drain balances
        mockEthcallProviderTryAll.mockResolvedValueOnce([
          { success: true, returnData: ethers.BigNumber.from(1000) }, // Victim (address1)
          { success: true, returnData: ethers.BigNumber.from(50) }, // Exploiter (address2)
        ]);
        // Balance call for post-drain balances
        mockEthcallProviderTryAll.mockResolvedValueOnce([
          { success: true, returnData: ethers.BigNumber.from(5) }, // Victim (address1)
          { success: true, returnData: ethers.BigNumber.from(1045) }, // Exploiter (address2)
        ]);

        // Adding one to each for the current transaction
        const mockAnomalyScore = (assetDrainedTransactions + 1) / (totalTransferTransactions + 1);

        await handleTransaction(mockTxEvent);
        const findings = await handleBlock(mockBlockEvent);
        expect(mockEthcallProviderTryAll).toHaveBeenCalledTimes(2);
        expect(findings).toStrictEqual([
          Finding.fromObject({
            name: "Asset drained",
            description: `99% or more of ${address1}'s ${symbol} tokens were drained`,
            alertId: "ASSET-DRAINED",
            severity: FindingSeverity.High,
            type: FindingType.Exploit,
            metadata: {
              contract: address1,
              asset,
              initiators: [address4],
              preDrainBalance: "1000",
              postDrainBalance: "5",
              txHashes: [ethers.utils.formatBytes32String("0x2352352")],
              blockNumber: 9999,
              anomalyScore: mockAnomalyScore.toFixed(2),
            },
            labels: [
              Label.fromObject({
                entityType: EntityType.Address,
                entity: address1,
                label: "Victim",
                confidence: 1,
              }),
            ],
            addresses: [address2],
          }),
        ]);
      });

      it("should not create an alert if the contract already had a 0 balance", async () => {
        const mockTransferEvent1 = {
          address: asset,
          args: {
            from: address1,
            to: address2,
            value: ethers.BigNumber.from(995),
          },
        };
        mockTxEvent.filterLog.mockReturnValueOnce([mockTransferEvent1]);
        // Balance call for pre-drain balances
        mockEthcallProviderTryAll.mockResolvedValueOnce([
          { success: true, returnData: ethers.BigNumber.from(0) }, // Victim (address1)
          { success: true, returnData: ethers.BigNumber.from(50) }, // Exploiter (address2)
        ]);
        // Balance call for post-drain balances
        mockEthcallProviderTryAll.mockResolvedValueOnce([
          { success: true, returnData: ethers.BigNumber.from(0) }, // Victim (address1)
          { success: true, returnData: ethers.BigNumber.from(1045) }, // Exploiter (address2)
        ]);

        await handleTransaction(mockTxEvent);
        const findings = await handleBlock(mockBlockEvent);
        expect(mockEthcallProviderTryAll).toHaveBeenCalledTimes(2);
        expect(findings).toStrictEqual([]);
      });

      it("should alert if there are contracts with assets fully drained in more than one tx in the same block", async () => {
        const mockTransferEvent1 = {
          address: asset,
          args: {
            from: address1,
            to: address2,
            value: ethers.BigNumber.from(400),
          },
        };
        const mockTransferEvent2 = {
          address: asset,
          args: {
            from: address1,
            to: address3,
            value: ethers.BigNumber.from(593),
          },
        };

        mockTxEvent.filterLog.mockReturnValueOnce([mockTransferEvent1]);
        mockTxEvent2.filterLog.mockReturnValueOnce([mockTransferEvent2]);
        // Balance call for pre-drain balances
        mockEthcallProviderTryAll.mockResolvedValueOnce([
          { success: true, returnData: ethers.BigNumber.from(1000) }, // Victim (address1)
          { success: true, returnData: ethers.BigNumber.from(50) }, // Exploiter 01 (address2)
          { success: true, returnData: ethers.BigNumber.from(75) }, // Exploiter 02 (address3)
        ]);
        // Balance call for post-drain balances
        mockEthcallProviderTryAll.mockResolvedValueOnce([
          { success: true, returnData: ethers.BigNumber.from(7) }, // Victim (address1)
          { success: true, returnData: ethers.BigNumber.from(450) }, // Exploiter 01 (address2)
          { success: true, returnData: ethers.BigNumber.from(668) }, // Exploiter 02 (address3)
        ]);

        // Adding one for the asset drained transaction, but two because it is handling two transactions
        const mockAnomalyScore = (assetDrainedTransactions + 1) / (totalTransferTransactions + 2);

        await handleTransaction(mockTxEvent);
        await handleTransaction(mockTxEvent2);
        const findings = await handleBlock(mockBlockEvent);
        expect(mockEthcallProviderTryAll).toHaveBeenCalledTimes(2);
        expect(findings).toStrictEqual([
          Finding.fromObject({
            name: "Asset drained",
            description: `99% or more of ${address1}'s ${symbol} tokens were drained`,
            alertId: "ASSET-DRAINED",
            severity: FindingSeverity.High,
            type: FindingType.Exploit,
            metadata: {
              contract: address1,
              asset,
              initiators: [address4, address5],
              preDrainBalance: "1000",
              postDrainBalance: "7",
              txHashes: [
                ethers.utils.formatBytes32String("0x2352352"),
                ethers.utils.formatBytes32String("0x442352352"),
              ],
              blockNumber: 9999,
              anomalyScore: mockAnomalyScore.toFixed(2),
            },
            labels: [
              Label.fromObject({
                entityType: EntityType.Address,
                entity: address1,
                label: "Victim",
                confidence: 1,
              }),
            ],
            addresses: [address2, address3],
          }),
        ]);
      });
    });

    describe("Persistence functionality", () => {
      afterEach(() => {
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
  });
});

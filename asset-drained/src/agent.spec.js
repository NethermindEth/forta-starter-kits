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

const mockCalculateRate = jest.fn();
const mockGetValueInUsd = jest.fn();
const mockGetTotalSupply = jest.fn();

const asset = createAddress("0x01");
const address1 = createAddress("0x02");
const address2 = createAddress("0x03");
const address3 = createAddress("0x04");
const address4 = createAddress("0x05");
const address5 = createAddress("0x06");
const address6 = createAddress("0x07");
const address7 = createAddress("0x08");

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
      mockTxEvent.filterLog.mockReturnValueOnce([]).mockReturnValueOnce([]).mockReturnValueOnce([]);
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
      mockTxEvent.filterLog
        .mockReturnValueOnce([])
        .mockReturnValueOnce([mockTransferEvent1, mockTransferEvent2])
        .mockReturnValueOnce([]);

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

      initialize = provideInitialize(mockProvider);

      await initialize();

      handleTransaction = provideHandleTransaction();

      handleBlock = provideHandleBlock(mockCalculateRate, mockGetValueInUsd, mockGetTotalSupply);

      mockTxEvent.filterLog.mockReset();
      mockTxEvent2.filterLog.mockReset();
      mockEthcallProviderTryAll.mockReset();
      Object.keys(getTransfersObj()).forEach((key) => delete getTransfersObj()[key]);
    });

    describe("Alert Generation", () => {
      const mockBlockEvent = { blockNumber: 10_001 }; // After implementing sharding, each block on Ethereum processes transations from 2 blocks ago (9999 -> 10001)

      it("should not alert if there are no transfers", async () => {
        mockTxEvent.filterLog.mockReturnValueOnce([]).mockReturnValueOnce([]).mockReturnValueOnce([]);
        await handleTransaction(mockTxEvent);
        const findings = await handleBlock(mockBlockEvent);
        expect(findings).toStrictEqual([]);
      });

      it("should alert if there are contracts that had 99% or more of their assets drained and the value is over threshold", async () => {
        const mockTransferEvent1 = {
          address: asset,
          args: {
            from: address1,
            to: address2,
            value: ethers.BigNumber.from(995),
          },
        };
        mockTxEvent.filterLog.mockReturnValueOnce([]).mockReturnValueOnce([mockTransferEvent1]).mockReturnValueOnce([]);
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

        mockCalculateRate.mockResolvedValueOnce(0.00000034234);
        mockGetValueInUsd.mockResolvedValueOnce(32000);

        global.fetch = jest.fn();
        global.fetch.mockResolvedValue({
          json: jest.fn().mockResolvedValue({
            status: "1",
            message: "OK",
            result: [
              {
                contractCreator: createAddress("0x1234"), // Random contract creator
              },
            ],
          }),
        });

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
              anomalyScore: (0.00000034234).toString(),
            },
            labels: [
              Label.fromObject({
                entityType: EntityType.Address,
                entity: address1,
                label: "Victim",
                confidence: 1,
              }),
              Label.fromObject({
                entityType: EntityType.Address,
                entity: address4,
                label: "Attacker",
                confidence: 0.5,
              }),
            ],
            addresses: [address2],
          }),
        ]);
      });

      it("should alert liquidity removal if there are contracts that had 99% or more of their assets drained by liquidity removal and the value is over threshold", async () => {
        const mockTransferEvent1 = {
          address: asset,
          args: {
            from: address1,
            to: address2,
            value: ethers.BigNumber.from(995),
          },
        };

        const mockBurnEvent = {
          address: asset,
          args: {
            sender: address6,
            amount0: ethers.BigNumber.from(100),
            amount1: ethers.BigNumber.from(10),
            to: address7,
          },
        };
        mockTxEvent.filterLog
          .mockReturnValueOnce([])
          .mockReturnValueOnce([mockTransferEvent1])
          .mockReturnValueOnce([mockBurnEvent]);
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

        mockCalculateRate.mockResolvedValueOnce(0.00000034234);
        mockGetValueInUsd.mockResolvedValueOnce(32000);

        await handleTransaction(mockTxEvent);
        const findings = await handleBlock(mockBlockEvent);
        expect(mockEthcallProviderTryAll).toHaveBeenCalledTimes(2);
        expect(findings).toStrictEqual([
          Finding.fromObject({
            name: "Asset drained",
            description: `99% or more of ${address1}'s ${symbol} tokens were drained`,
            alertId: "ASSET-DRAINED-LIQUIDITY-REMOVAL",
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
              anomalyScore: (0.00000034234).toString(),
            },
            labels: [
              Label.fromObject({
                entityType: EntityType.Address,
                entity: address1,
                label: "Victim",
                confidence: 1,
              }),
              Label.fromObject({
                entityType: EntityType.Address,
                entity: address4,
                label: "Attacker",
                confidence: 0.5,
              }),
            ],
            addresses: [address2],
          }),
        ]);
      });

      it("should alert if there are contracts that had 99% or more of their assets drained but the value lost is under threshold", async () => {
        const mockTransferEvent1 = {
          address: asset,
          args: {
            from: address1,
            to: address2,
            value: ethers.BigNumber.from(995),
          },
        };
        mockTxEvent.filterLog.mockReturnValueOnce([]).mockReturnValueOnce([mockTransferEvent1]).mockReturnValueOnce([]);
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

        mockGetValueInUsd.mockResolvedValueOnce(2000);

        await handleTransaction(mockTxEvent);
        const findings = await handleBlock(mockBlockEvent);
        expect(mockEthcallProviderTryAll).toHaveBeenCalledTimes(2);
        expect(findings).toStrictEqual([]);
      });

      it("should alert if there are contracts that had 99% or more of their assets drained, the value is 0, but the amount lost is over the total supply percentage threshold", async () => {
        const mockTransferEvent1 = {
          address: asset,
          args: {
            from: address1,
            to: address2,
            value: ethers.BigNumber.from(995),
          },
        };
        mockTxEvent.filterLog.mockReturnValueOnce([]).mockReturnValueOnce([mockTransferEvent1]).mockReturnValueOnce([]);
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

        mockGetValueInUsd.mockResolvedValueOnce(0);
        mockGetTotalSupply.mockResolvedValueOnce(ethers.BigNumber.from(2000));
        mockCalculateRate.mockResolvedValueOnce(0.000000534234);

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
              anomalyScore: (0.000000534234).toString(),
            },
            labels: [
              Label.fromObject({
                entityType: EntityType.Address,
                entity: address1,
                label: "Victim",
                confidence: 1,
              }),
              Label.fromObject({
                entityType: EntityType.Address,
                entity: address4,
                label: "Attacker",
                confidence: 0.5,
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
        mockTxEvent.filterLog.mockReturnValueOnce([]).mockReturnValueOnce([mockTransferEvent1]).mockReturnValueOnce([]);
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

        mockTxEvent.filterLog.mockReturnValueOnce([]).mockReturnValueOnce([mockTransferEvent1]).mockReturnValueOnce([]);
        mockTxEvent2.filterLog
          .mockReturnValueOnce([])
          .mockReturnValueOnce([mockTransferEvent2])
          .mockReturnValueOnce([]);
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

        mockCalculateRate.mockResolvedValueOnce(0.000000934234);
        mockGetValueInUsd.mockResolvedValueOnce(32000);

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
              anomalyScore: (0.000000934234).toString(),
            },
            labels: [
              Label.fromObject({
                entityType: EntityType.Address,
                entity: address1,
                label: "Victim",
                confidence: 1,
              }),
              Label.fromObject({
                entityType: EntityType.Address,
                entity: address4,
                label: "Attacker",
                confidence: 0.5,
              }),
              Label.fromObject({
                entityType: EntityType.Address,
                entity: address5,
                label: "Attacker",
                confidence: 0.5,
              }),
            ],
            addresses: [address2, address3],
          }),
        ]);
      });

      it("should not alert when the drainer is the contract creator in cases other than liquidity removal", async () => {
        const mockTransferEvent1 = {
          address: asset,
          args: {
            from: address1,
            to: address2,
            value: ethers.BigNumber.from(995),
          },
        };
        mockTxEvent.filterLog.mockReturnValueOnce([]).mockReturnValueOnce([mockTransferEvent1]).mockReturnValueOnce([]);
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

        mockCalculateRate.mockResolvedValueOnce(0.00000034234);
        mockGetValueInUsd.mockResolvedValueOnce(32000);

        global.fetch = jest.fn();
        global.fetch.mockResolvedValue({
          json: jest.fn().mockResolvedValue({
            status: "1",
            message: "OK",
            result: [
              {
                contractCreator: address4, // Tx Initiator
              },
            ],
          }),
        });

        await handleTransaction(mockTxEvent);
        const findings = await handleBlock(mockBlockEvent);
        expect(mockEthcallProviderTryAll).toHaveBeenCalledTimes(2);
        expect(findings).toStrictEqual([]);
      });
    });
  });
});

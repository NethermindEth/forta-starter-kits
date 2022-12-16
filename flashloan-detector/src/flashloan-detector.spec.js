/* eslint-disable no-plusplus */
const { ethers } = require("forta-agent");
const { getFlashloans } = require("./flashloan-detector");

const asset = "0xasset";
const amount = ethers.utils.parseUnits("100", 18);
const account = "0xaccount";
const market = "0xmarket";

jest.mock("forta-agent", () => {
  const original = jest.requireActual("forta-agent");
  return {
    ...original,
    getEthersProvider: jest.fn(),
    ethers: {
      ...original.ethers,
      Contract: jest.fn().mockImplementation(() => ({
        getMarket: () => [asset],
        underlying: () => asset,
        token0: () => asset,
      })),
    },
  };
});

const mockAaveV2Event = {
  args: { asset, amount, target: account },
};

const mockAaveV3Event = {
  args: { asset, amount, target: account },
};

const mockDydxWithdrawEvent = {
  address: market,
  args: {
    market: ethers.constants.Zero,
    accountOwner: account,
    from: account,
    update: {
      deltaWei: {
        sign: false,
        value: amount,
      },
    },
  },
};

const mockDydxDepositEvent = {
  address: market,
  args: {
    market: ethers.constants.Zero,
    accountOwner: account,
    from: account,
    update: {
      deltaWei: {
        sign: true,
        value: amount.add(2),
      },
    },
  },
};

const mockEulerBorrowEvent = {
  name: "Borrow",
  address: market,
  args: {
    amount,
    underlying: asset,
    account,
  },
};

const mockEulerRepayEvent = {
  name: "Repay",
  address: market,
  args: {
    amount,
    underlying: asset,
    account,
  },
};

const mockEulerRequestBorrowEvent = {
  name: "RequestBorrow",
  address: market,
  args: {
    amount,
    account,
  },
};

const mockIronBankEvent = {
  args: { amount, receiver: account },
};

const mockMakerEvent = {
  args: { token: asset, amount, receiver: account },
};

const mockUniswapV2FunctionCall = {
  address: market,
  args: {
    to: account,
    data: "0x00",
    amount0Out: amount,
    amount1Out: ethers.constants.Zero,
  },
};

const mockUniswapV3FunctionCall = {
  address: market,
  args: {
    recipient: account,
    amount0: amount,
    amount1: ethers.constants.Zero,
  },
};

const mockBalancererEvent = {
  args: { token: asset, amount, receiver: account },
};

describe("FlashloanDetector library", () => {
  const mockTxEvent = {
    filterLog: jest.fn(),
    filterFunction: jest.fn(),
  };

  beforeEach(() => {
    mockTxEvent.filterLog.mockReset();
    mockTxEvent.filterFunction.mockReset();
  });

  describe("getFlashloans", () => {
    it("should return empty array if there are no flashloans", async () => {
      // Don't mock
      mockTxEvent.filterLog.mockReturnValue([]);
      mockTxEvent.filterFunction.mockReturnValue([]);
      const flashloans = await getFlashloans(mockTxEvent);

      expect(flashloans).toStrictEqual([]);
    });

    it("should return all the protocols if there is a flashloan from all", async () => {
      mockTxEvent.filterLog.mockReturnValueOnce([mockAaveV2Event]);
      mockTxEvent.filterLog.mockReturnValueOnce([mockAaveV3Event]);
      mockTxEvent.filterLog.mockReturnValueOnce([mockDydxDepositEvent, mockDydxWithdrawEvent]);
      mockTxEvent.filterLog.mockReturnValueOnce([
        mockEulerRequestBorrowEvent,
        mockEulerBorrowEvent,
        mockEulerRepayEvent,
      ]);
      mockTxEvent.filterLog.mockReturnValueOnce([mockIronBankEvent]);
      mockTxEvent.filterLog.mockReturnValueOnce([mockMakerEvent]);
      mockTxEvent.filterFunction.mockReturnValueOnce([mockUniswapV2FunctionCall]);
      mockTxEvent.filterFunction.mockReturnValueOnce([mockUniswapV3FunctionCall]);
      mockTxEvent.filterLog.mockReturnValueOnce([mockBalancererEvent]);
      const flashloans = await getFlashloans(mockTxEvent);

      const expectedFlashloanData = { account, amount, asset };
      const expectedArray = [];

      // 8 flashloans: aaveV2, aaveV3, dydx, euler, iron bank, maker, uniswap V2, uniswap V3, balancer
      for (let i = 0; i < 9; i++) {
        expectedArray.push(expectedFlashloanData);
      }

      expect(flashloans).toStrictEqual(expectedArray);
    });
  });
});

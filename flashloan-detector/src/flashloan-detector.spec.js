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
        _QUOTE_TOKEN_: () => asset,
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
    data: "0x0" + "0".repeat(64), // Data length should be more 32 bytes (64 hex characters)
    amount0Out: amount,
    amount1Out: ethers.constants.Zero,
  },
};

const mockUniswapV2Event = {
  address: market,
  args: {
    to: account,
    amount0Out: amount,
    amount1Out: ethers.constants.Zero,
  },
};

const mockUniswapV3Event = {
  address: market,
  args: {
    recipient: account,
    amount0: amount,
    amount1: ethers.constants.Zero,
  },
};

const mockBalancerEvent = {
  args: { token: asset, amount, receiver: account },
};

const mockDodoFlashLoanEvent = {
  address: "0xdefi",
  args: { baseAmount: ethers.constants.Zero, quoteAmount: amount, assetTo: account },
};

describe("FlashloanDetector library", () => {
  const mockTxEvent = {
    filterLog: jest.fn(),
    filterFunction: jest.fn(),
    transaction: {
      data: "0x0",
    },
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
      mockTxEvent.filterLog.mockReturnValueOnce([mockUniswapV2Event]);
      mockTxEvent.filterLog.mockReturnValueOnce([mockUniswapV3Event]);
      // Checking for a `swap` in UniswapV3 Pool
      mockTxEvent.filterFunction.mockReturnValueOnce([]);
      mockTxEvent.filterLog.mockReturnValueOnce([mockBalancerEvent]);
      mockTxEvent.filterLog.mockReturnValueOnce([mockDodoFlashLoanEvent]);
      const flashloans = await getFlashloans(mockTxEvent);

      const expectedFlashloanData = { account, amount, asset };
      const expectedArray = [];

      // 10 flashloans:
      // 1. aaveV2, 2. aaveV3, 3. dydx, 4. euler, 5. iron bank
      // 6. maker, 7. uniswap V2, 8. uniswap V3, 9. balancer, 10. DODO
      for (let i = 0; i < 10; i++) {
        expectedArray.push(expectedFlashloanData);
      }

      expect(flashloans).toStrictEqual(expectedArray);
    });
  });
});

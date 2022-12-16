const { Finding, FindingSeverity, FindingType, ethers } = require("forta-agent");
const { getFlashloans: getFlashloansFn } = require("./flashloan-detector");
const helperModule = require("./helper");

let chain;
let nativeToken;

const PROFIT_THRESHOLD = 500_000;
const PERCENTAGE_THRESHOLD = 2;
const PROFIT_THRESHOLD_WITH_HIGH_PERCENTAGE = 100_000;

function provideInitialize(helper) {
  return async function initialize() {
    ({ chain, nativeToken } = await helper.init());
  };
}

const transferEventSigs = [
  "event Transfer(address indexed src, address indexed dst, uint wad)",
  "event Withdrawal(address indexed src, uint256 wad)",
];

function provideHandleTransaction(helper, getFlashloans) {
  return async function handleTransaction(txEvent) {
    const findings = [];
    const initiator = txEvent.from;

    const flashloans = await getFlashloans(txEvent);
    if (flashloans.length === 0) return findings;

    const calledContract = txEvent.to;
    const transferEvents = txEvent.filterLog(transferEventSigs);
    const { traces } = txEvent;

    let totalTokenProfits = {};
    let totalNativeProfit = helper.zero;
    let totalBorrowed = 0;

    // For each flashloan calculate the token profits and the borrowed amount
    await Promise.all(
      flashloans.map(async (flashloan) => {
        const { asset, amount, account } = flashloan;

        if (account !== initiator) {
          const tokenProfits = helper.calculateTokenProfits(transferEvents, account);
          const nativeProfit = helper.calculateNativeProfit(traces, account);

          Object.entries(tokenProfits).forEach(([address, profit]) => {
            if (!totalTokenProfits[address]) totalTokenProfits[address] = helper.zero;
            totalTokenProfits[address] = totalTokenProfits[address].add(profit);
          });
          totalNativeProfit = nativeProfit.add(nativeProfit);
        }

        // Iterating through back of Transfers to find recipient of end profit
        for (let i = transferEvents.length - 1; i >= 0; i--) {
          const { name } = transferEvents[i];
          const { src, dst } = transferEvents[i].args;

          if (name === "Transfer" && src.toLowerCase() === calledContract && dst.toLowerCase() === initiator) {
            const tokenProfits = helper.calculateTokenProfits(transferEvents, initiator);
            const positiveProfits = Object.values(tokenProfits).filter((i) => i > helper.zero);
            if (positiveProfits.length === 0) {
              continue;
            }

            Object.entries(tokenProfits).forEach(([address, profit]) => {
              if (!totalTokenProfits[address]) totalTokenProfits[address] = helper.zero;
              totalTokenProfits[address] = totalTokenProfits[address].add(profit);
            });
            break;
          } else if (name === "Transfer" && src.toLowerCase() === account && dst.toLowerCase() === initiator) {
            const tokenProfits = helper.calculateTokenProfits(transferEvents, initiator);
            const positiveProfits = Object.values(tokenProfits).filter((i) => i > helper.zero);
            if (positiveProfits.length === 0) {
              continue;
            }

            Object.entries(tokenProfits).forEach(([address, profit]) => {
              if (!totalTokenProfits[address]) totalTokenProfits[address] = helper.zero;
              totalTokenProfits[address] = totalTokenProfits[address].add(profit);
            });
            break;
          } else if (name === "Transfer" && src.toLowerCase() === calledContract) {
            const tokenProfits = helper.calculateTokenProfits(transferEvents, dst.toLowerCase());
            const positiveProfits = Object.values(tokenProfits).filter((i) => i > helper.zero);
            if (positiveProfits.length === 0) {
              continue;
            }

            Object.entries(tokenProfits).forEach(([address, profit]) => {
              if (!totalTokenProfits[address]) totalTokenProfits[address] = helper.zero;
              totalTokenProfits[address] = totalTokenProfits[address].add(profit);
            });
            break;
          } else if (name === "Transfer" && src.toLowerCase() === account) {
            const tokenProfits = helper.calculateTokenProfits(transferEvents, dst.toLowerCase());
            const positiveProfits = Object.values(tokenProfits).filter((i) => i > helper.zero);
            if (positiveProfits.length === 0) {
              continue;
            }

            Object.entries(tokenProfits).forEach(([address, profit]) => {
              if (!totalTokenProfits[address]) totalTokenProfits[address] = helper.zero;
              totalTokenProfits[address] = totalTokenProfits[address].add(profit);
            });
            break;
          }
        }

        for (let i = traces.length - 1; i >= 0; i--) {
          const { from, to, value, callType } = traces[i].action;

          if (value && value !== "0x0" && callType === "call" && to.toLowerCase() === initiator) {
            const nativeProfit = helper.calculateNativeProfit(traces, initiator);
            totalNativeProfit = totalNativeProfit.add(nativeProfit);
            break;
          } else if (value && value !== "0x0" && callType === "call" && from.toLowerCase() === account) {
            const dstAddress = to.toLowerCase();
            const nativeProfit = helper.calculateNativeProfit(traces, dstAddress);
            if (nativeProfit === helper.zero) {
              continue;
            }

            totalNativeProfit = totalNativeProfit.add(nativeProfit);
            break;
          }
        }

        totalBorrowed = await helper.calculateBorrowedAmount(asset, amount, chain);
      })
    );

    // Subtract the tx fee
    const { gasUsed } = await helper.getTransactionReceipt(txEvent.hash);
    const { gasPrice } = txEvent.transaction;
    const txFee = ethers.BigNumber.from(gasUsed).mul(ethers.BigNumber.from(gasPrice));
    totalNativeProfit = totalNativeProfit.sub(txFee);

    let tokensUsdProfit = 0;
    let nativeUsdProfit = 0;

    const tokensArray = Object.keys(totalTokenProfits);

    if (tokensArray.length !== 0) {
      tokensUsdProfit = await helper.calculateTokensUsdProfit(totalTokenProfits, chain);
    }

    if (!totalNativeProfit.isZero()) {
      nativeUsdProfit = await helper.calculateNativeUsdProfit(totalNativeProfit, nativeToken);
    }

    const totalProfit = tokensUsdProfit + nativeUsdProfit;
    const percentage = (totalProfit / totalBorrowed) * 100;

    console.log("Chain     :", chain);
    console.log("TX hash   :", txEvent.hash);
    console.log("Borrowed  :", totalBorrowed.toFixed(2));
    console.log("Profit    :", totalProfit.toFixed(2));
    console.log("Percentage:", percentage.toFixed(2));

    if (percentage > PERCENTAGE_THRESHOLD && totalProfit > PROFIT_THRESHOLD_WITH_HIGH_PERCENTAGE) {
      findings.push(
        Finding.fromObject({
          name: "Flashloan detected",
          description: `${initiator} launched flash loan attack and made profit > $${PROFIT_THRESHOLD_WITH_HIGH_PERCENTAGE}`,
          alertId: "FLASHLOAN-ATTACK-WITH-HIGH-PROFIT",
          severity: FindingSeverity.High,
          type: FindingType.Exploit,
          metadata: {
            profit: totalProfit.toFixed(2),
            tokens: tokensArray,
          },
        })
      );
    } else if (percentage > PERCENTAGE_THRESHOLD) {
      findings.push(
        Finding.fromObject({
          name: "Flashloan detected",
          description: `${initiator} launched flash loan attack`,
          alertId: "FLASHLOAN-ATTACK",
          severity: FindingSeverity.Low,
          type: FindingType.Exploit,
          metadata: {
            profit: totalProfit.toFixed(2),
            tokens: tokensArray,
          },
        })
      );
    } else if (totalProfit > PROFIT_THRESHOLD) {
      findings.push(
        Finding.fromObject({
          name: "Flashloan detected",
          description: `${initiator} launched flash loan attack and made profit > $${PROFIT_THRESHOLD}`,
          alertId: "FLASHLOAN-ATTACK-WITH-HIGH-PROFIT",
          severity: FindingSeverity.High,
          type: FindingType.Exploit,
          metadata: {
            profit: totalProfit.toFixed(2),
            tokens: tokensArray,
          },
        })
      );
    }

    // Clear all cached prices and delete token decimals if the object is too large
    helper.clear();

    return findings;
  };
}

module.exports = {
  provideInitialize,
  initialize: provideInitialize(helperModule),
  provideHandleTransaction,
  handleTransaction: provideHandleTransaction(helperModule, getFlashloansFn),
};

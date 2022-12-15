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
    const initiator = txEvent.from.toLowerCase();

    // flashloans[0].account IS THE BORROWER CONTRACT
    // OF THE FLASHLOAN, THAT THEN SENDS THE TRANSFER
    // TO THE EOA
    const flashloans = await getFlashloans(txEvent);
    if (flashloans.length === 0) return findings;

    // transferEvents[17] IS THE CORRECT TRANSFER,
    // THAT SENT THE PROFIT FROM THE BORROWER CONTRACT
    // TO THE END RECIPIENT, WHO HAPPENS TO BE THE
    // INITIATOR EOA IN THIS TRANSACTION
    const transferEvents = txEvent.filterLog(transferEventSigs);
    const { traces } = txEvent;
    
    console.log("the last transferEvents is: " + JSON.stringify(transferEvents[transferEvents.length - 1]));

    // Set the initial total profit to the end recipient's profit
    let totalTokenProfits = {};
    let totalNativeProfit = helper.zero;
    let totalBorrowed = 0;

    // For each flashloan calculate the token profits and the borrowed amount
    const flashloansData = await Promise.all(
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

        // Iterating from the end to find the profitable transfer instance
        for(let i = transferEvents.length -1; i >= 0; i--) {
          if(transferEvents[i].name === "Transfer" && transferEvents[i].args.src.toLowerCase() === account) {
            const _endRecipient = transferEvents[i].args.dst.toLowerCase();
            const tokenProfits = helper.calculateTokenProfits(transferEvents, _endRecipient);
            const nativeProfit = helper.calculateNativeProfit(traces, _endRecipient);

            // ADD PROFIT TO THE DECLARED OBJECTS.
            Object.entries(tokenProfits).forEach(([address, profit]) => {
              if (!totalTokenProfits[address]) totalTokenProfits[address] = helper.zero;
              totalTokenProfits[address] = totalTokenProfits[address].add(profit);
            });
            totalNativeProfit = totalNativeProfit.add(nativeProfit);
          }
        }

        // ORIGINAL
        // const borrowedAmountUsd = await helper.calculateBorrowedAmount(asset, amount, chain);
        totalBorrowed = await helper.calculateBorrowedAmount(asset, amount, chain);
        // return { tokenProfits, nativeProfit, borrowedAmountUsd };
      })
    );

    console.log(`totalTokenProfits is ${JSON.stringify(totalTokenProfits)}; totalNativeProfit is ${totalNativeProfit}; totalBorrowed is ${totalBorrowed}.`);

    /*
    // Set the initial total profit to the end recipient's profit
    const totalTokenProfits = helper.calculateTokenProfits(transferEvents, endRecipient);
    let totalNativeProfit = helper.calculateNativeProfit(traces, endRecipient);
    let totalBorrowed = 0;
    */

    // Subtract the tx fee
    const { gasUsed } = await helper.getTransactionReceipt(txEvent.hash);
    const { gasPrice } = txEvent.transaction;
    const txFee = ethers.BigNumber.from(gasUsed).mul(ethers.BigNumber.from(gasPrice));
    totalNativeProfit = totalNativeProfit.sub(txFee);

    /*
    // MOVED TO INSIDE THE Flashloan LOOP
    flashloansData.forEach((flashloan) => {
      const { tokenProfits, nativeProfit, borrowedAmountUsd } = flashloan;

      // Set initial value and add the profit for the asset to the total
      Object.entries(tokenProfits).forEach(([address, profit]) => {
        if (!totalTokenProfits[address]) totalTokenProfits[address] = helper.zero;
        totalTokenProfits[address] = totalTokenProfits[address].add(profit);
      });

      totalNativeProfit = totalNativeProfit.add(nativeProfit);
      totalBorrowed += borrowedAmountUsd;
    });
    */

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

const balancerFlashloanSig = "event FlashLoan(address indexed receiver, address indexed token, uint256 amount, uint256 feeAmount)";

module.exports = {
  getBalancerFlashloan: (txEvent) => {
    const flashloans = [];
    const events = txEvent.filterLog(balancerFlashloanSig);

    events.forEach((event) => {
      const { token, amount, receiver } = event.args;
      flashloans.push({
        asset: token.toLowerCase(),
        amount,
        account: receiver.toLowerCase(),
      });
    });
    return flashloans;
  },
};
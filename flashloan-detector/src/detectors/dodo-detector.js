const { ethers, getEthersProvider } = require("forta-agent");

const dodoFlashloanAbi = "DODOFlashLoan (address borrower, address assetTo, uint256 baseAmount, uint256 quoteAmount)";

const dodoPoolAbi = [
    "function _BASE_TOKEN_ public view returns (address)",
    "function _QUOTE_TOKEN_ public view returns (address)"
];

module.exports = {
    getDodoFlashloan: (txEvent) => {
        const flashloans = [];
        const events = txEvent.filterLog(dodoFlashloanAbi);

        events.forEach(async (event) => {
            const { address } = event;
            const { assetTo, baseAmount, quoteAmount } = event.args;

            const contract = new ethers.Contract(address, dodoPoolAbi, getEthersProvider());

            if(quoteAmount.gt(ethers.constants.Zero)) {
                const quoteToken = await contract._QUOTE_TOKEN_();

                flashloans.push({
                    asset: quoteToken.toLowerCase(),
                    amount: quoteAmount,
                    account: assetTo.toLowerCase()
                });
            };
            
            if(baseAmount.gt(ethers.constants.Zero)) {
                const baseToken = await contract._BASE_TOKEN_();

                flashloans.push({
                    asset: baseToken.toLowerCase(),
                    amount: baseAmount,
                    account: assetTo.toLowerCase()
                });
            };

        });
        return flashloans;
    },
  };
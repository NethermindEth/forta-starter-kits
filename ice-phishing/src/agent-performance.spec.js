const { getEthersProvider, createTransactionEvent, createBlockEvent } = require("forta-agent");
const { default: calculateAlertRate } = require("bot-alert-rate");
const {
  provideInitialize,
  provideHandleTransaction,
  provideHandleBlock,
  resetInit,
  counters,
  DATABASE_URL,
  DATABASE_KEYS,
  DATABASE_OBJECT_KEY,
} = require("./agent");
const { getSuspiciousContracts, getFailSafeWallets } = require("./helper");
const { PersistenceHelper } = require("./persistence.helper");

const approveCountThreshold = 0;
const approveForAllCountThreshold = 0;
const transferCountThreshold = 0;
const timePeriodDays = 30;
const nonceThreshold = 100;
const maxAddressAlertsPerPeriod = 3;
const contractTxsThreshold = 4999;
const verifiedContractTxsThreshold = 1999;

jest.setTimeout(1000000);

// Mock the config file
jest.mock(
  "../bot-config.json",
  () => ({
    approveCountThreshold,
    approveForAllCountThreshold,
    transferCountThreshold,
    timePeriodDays,
    nonceThreshold,
    contractTxsThreshold,
    verifiedContractTxsThreshold,
    maxAddressAlertsPerPeriod,
  }),
  { virtual: true }
);

describe("Ice Phishing bot performance test", () => {
  it("tests performance", async () => {
    const realProvider = getEthersProvider();
    let initialize = provideInitialize(
      realProvider,
      new PersistenceHelper(DATABASE_URL),
      DATABASE_KEYS,
      counters,
      DATABASE_OBJECT_KEY
    );
    let handleBlock = provideHandleBlock(
      getSuspiciousContracts,
      getFailSafeWallets,
      new PersistenceHelper(DATABASE_URL),
      DATABASE_KEYS,
      DATABASE_OBJECT_KEY,
      counters,
      1
    );
    let handleTransaction = provideHandleTransaction(
      realProvider,
      counters,
      DATABASE_OBJECT_KEY,
      new PersistenceHelper(DATABASE_URL),
      calculateAlertRate,
      0
    );

    await initialize();

    const blocksToRun = 5;

    //     Chain: Blocktime, Number of Tx -> Avg processing time in ms target
    //     Ethereum: 12s, 150 -> 80ms
    //     BSC: 3s, 70 -> 43ms
    //     Polygon: 2s, 50 -> 40ms
    //     Arbitrum: 1s, 5 -> 200ms
    //     Optimism: 24s, 150 -> 160ms
    //     Avalanche: 2s, 5 -> 400ms
    //     Fantom: 1s, 5 -> 200ms

    //      local testing reveals an avg processing time of 680*, which results in the following sharding config:
    //      Ethereum: 12s, 150 -> 80ms - 9
    //      BSC: 3s, 70 -> 43ms - 16
    //      Polygon: 2s, 50 -> 40ms - 17
    //      Arbitrum: 1s, 5 -> 200ms - 4
    //      Optimism: 24s, 150 -> 160ms - 5
    //      Avalanche: 2s, 5 -> 400ms - 2
    //      Fantom: 1s, 5 -> 200ms - 4

    //  * - subtracting ~600ms from the processing time to account for the time it takes to fetch the block's transactions and the data from the Scam Sniffer DB (which happens once per block)

    const normalTxEvent = createTransactionEvent({
      transaction: {
        hash: "hash",
        from: "0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
        to: "0x7a250d5630b4cf539739df2c5dacb4c659f2488d", // Uniswap Router
      },
      block: {
        number: 1236856,
        timestamp: 1684408535,
      },
    });

    // ------ ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS-INFO ------
    const erc20ApprovalsInfoTxReceipt = await realProvider.getTransactionReceipt(
      "0xac883804404eafae2d9f49a228145c0384d51ca25ef8e6dda215b7f20a4332dc"
    );

    const erc20ApprovalsInfoTx = await realProvider.getTransaction(
      "0xac883804404eafae2d9f49a228145c0384d51ca25ef8e6dda215b7f20a4332dc"
    );

    // Lowercase all addresses in logs to match the real txEvent logs
    const erc20ApprovalsInfoLowerCaseLogs = erc20ApprovalsInfoTxReceipt.logs.map((log) => {
      return {
        ...log,
        address: log.address.toLowerCase(),
      };
    });

    const erc20ApprovalsInfoTxEvent = createTransactionEvent({
      transaction: {
        hash: erc20ApprovalsInfoTxReceipt.transactionHash,
        from: erc20ApprovalsInfoTxReceipt.from.toLowerCase(),
        to: erc20ApprovalsInfoTxReceipt.to.toLowerCase(),
        nonce: erc20ApprovalsInfoTx.nonce,
        data: erc20ApprovalsInfoTx.data,
        gas: "1",
        gasPrice: erc20ApprovalsInfoTx.gasPrice.toString(),
        value: "0x0",
        r: erc20ApprovalsInfoTx.r,
        s: erc20ApprovalsInfoTx.s,
        v: erc20ApprovalsInfoTx.v.toFixed(),
      },
      block: {
        number: erc20ApprovalsInfoTxReceipt.blockNumber,
        hash: erc20ApprovalsInfoTxReceipt.blockHash,
        timestamp: 1684408535,
      },
      logs: erc20ApprovalsInfoLowerCaseLogs,
      contractAddress: null,
    });

    // ------ ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS ------
    const erc20ApprovalsTxReceipt = await realProvider.getTransactionReceipt(
      "0x56cd634c8829041daa877b2d873004595176d199647fcb89330c12e1956a0174"
    );

    const erc20ApprovalsTx = await realProvider.getTransaction(
      "0x56cd634c8829041daa877b2d873004595176d199647fcb89330c12e1956a0174"
    );

    // Lowercase all addresses in logs to match the real txEvent logs
    const erc20ApprovalsLowerCaseLogs = erc20ApprovalsTxReceipt.logs.map((log) => {
      return {
        ...log,
        address: log.address.toLowerCase(),
      };
    });

    const erc20ApprovalsTxEvent = createTransactionEvent({
      transaction: {
        hash: erc20ApprovalsTxReceipt.transactionHash,
        from: erc20ApprovalsTxReceipt.from.toLowerCase(),
        to: erc20ApprovalsTxReceipt.to.toLowerCase(),
        nonce: erc20ApprovalsTx.nonce,
        data: erc20ApprovalsTx.data,
        gas: "1",
        gasPrice: erc20ApprovalsTx.gasPrice.toString(),
        value: "0x0",
        r: erc20ApprovalsTx.r,
        s: erc20ApprovalsTx.s,
        v: erc20ApprovalsTx.v.toFixed(),
      },
      block: {
        number: erc20ApprovalsTxReceipt.blockNumber,
        hash: erc20ApprovalsTxReceipt.blockHash,
        timestamp: 1684408535,
      },
      logs: erc20ApprovalsLowerCaseLogs,
      contractAddress: null,
    });

    // ------ ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS-INFO ------
    const erc721ApprovalsInfoTxReceipt = await realProvider.getTransactionReceipt(
      "0xaaf32fa2598dba1da27874eb767a2c34f63422e9b551cf7442ece56ad9f3a189"
    );

    const erc721ApprovalsInfoTx = await realProvider.getTransaction(
      "0xaaf32fa2598dba1da27874eb767a2c34f63422e9b551cf7442ece56ad9f3a189"
    );

    // Lowercase all addresses in logs to match the real txEvent logs
    const erc721ApprovalsInfoLowerCaseLogs = erc721ApprovalsInfoTxReceipt.logs.map((log) => {
      return {
        ...log,
        address: log.address.toLowerCase(),
      };
    });

    const erc721ApprovalsInfoTxEvent = createTransactionEvent({
      transaction: {
        hash: erc721ApprovalsInfoTxReceipt.transactionHash,
        from: erc721ApprovalsInfoTxReceipt.from.toLowerCase(),
        to: erc721ApprovalsInfoTxReceipt.to.toLowerCase(),
        nonce: erc721ApprovalsInfoTx.nonce,
        data: erc721ApprovalsInfoTx.data,
        gas: "1",
        gasPrice: erc721ApprovalsInfoTx.gasPrice.toString(),
        value: "0x0",
        r: erc721ApprovalsInfoTx.r,
        s: erc721ApprovalsInfoTx.s,
        v: erc721ApprovalsInfoTx.v.toFixed(),
      },
      block: {
        number: erc721ApprovalsInfoTxReceipt.blockNumber,
        hash: erc721ApprovalsInfoTxReceipt.blockHash,
        timestamp: 1684408535,
      },
      logs: erc721ApprovalsInfoLowerCaseLogs,
      contractAddress: null,
    });

    // ------ ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS ------
    const erc721ApprovalsTxReceipt = await realProvider.getTransactionReceipt(
      "0xac70ed8f605cc51435bfe163d1ade9b5ac84b472f2680fd27cd5d895677794e9"
    );

    const erc721ApprovalsTx = await realProvider.getTransaction(
      "0xac70ed8f605cc51435bfe163d1ade9b5ac84b472f2680fd27cd5d895677794e9"
    );

    // Lowercase all addresses in logs to match the real txEvent logs
    const erc721ApprovalsLowerCaseLogs = erc721ApprovalsTxReceipt.logs.map((log) => {
      return {
        ...log,
        address: log.address.toLowerCase(),
      };
    });

    const erc721ApprovalsTxEvent = createTransactionEvent({
      transaction: {
        hash: erc721ApprovalsTxReceipt.transactionHash,
        from: erc721ApprovalsTxReceipt.from.toLowerCase(),
        to: erc721ApprovalsTxReceipt.to.toLowerCase(),
        nonce: erc721ApprovalsTx.nonce,
        data: erc721ApprovalsTx.data,
        gas: "1",
        gasPrice: erc721ApprovalsTx.gasPrice.toString(),
        value: "0x0",
        r: erc721ApprovalsTx.r,
        s: erc721ApprovalsTx.s,
        v: erc721ApprovalsTx.v.toFixed(),
      },
      block: {
        number: erc721ApprovalsTxReceipt.blockNumber,
        hash: erc721ApprovalsTxReceipt.blockHash,
        timestamp: 1684408535,
      },
      logs: erc721ApprovalsLowerCaseLogs,
      contractAddress: null,
    });

    // ------ ICE-PHISHING-ERC20-PERMIT ------
    const erc20PermitTxReceipt = await realProvider.getTransactionReceipt(
      "0x8b6b44aa77e6610c5090580b1a7dabec8304b4907efacf4016670b7dcfd2371f"
    );

    const erc20PermitTx = await realProvider.getTransaction(
      "0x8b6b44aa77e6610c5090580b1a7dabec8304b4907efacf4016670b7dcfd2371f"
    );

    // Lowercase all addresses in logs to match the real txEvent logs
    const erc20PermitLowerCaseLogs = erc20PermitTxReceipt.logs.map((log) => {
      return {
        ...log,
        address: log.address.toLowerCase(),
      };
    });

    const erc20PermitTxEvent = createTransactionEvent({
      transaction: {
        hash: erc20PermitTxReceipt.transactionHash,
        from: erc20PermitTxReceipt.from.toLowerCase(),
        to: erc20PermitTxReceipt.to.toLowerCase(),
        nonce: erc20PermitTx.nonce,
        data: erc20PermitTx.data,
        gas: "1",
        gasPrice: erc20PermitTx.gasPrice.toString(),
        value: "0x0",
        r: erc20PermitTx.r,
        s: erc20PermitTx.s,
        v: erc20PermitTx.v.toFixed(),
      },
      block: {
        number: erc20PermitTxReceipt.blockNumber,
        hash: erc20PermitTxReceipt.blockHash,
        timestamp: 1684408535,
      },
      logs: erc20PermitLowerCaseLogs,
      contractAddress: null,
    });

    // ------ ICE-PHISHING-ERC20-PERMIT-INFO ------
    const erc20PermitInfoTxReceipt = await realProvider.getTransactionReceipt(
      "0xac3f61f11bf037430bd495d5975a70a30f60f5ea00a93a879b137b75b6f7e3b7"
    );

    const erc20PermitInfoTx = await realProvider.getTransaction(
      "0xac3f61f11bf037430bd495d5975a70a30f60f5ea00a93a879b137b75b6f7e3b7"
    );

    // Lowercase all addresses in logs to match the real txEvent logs
    const erc20PermitInfoLowerCaseLogs = erc20PermitInfoTxReceipt.logs.map((log) => {
      return {
        ...log,
        address: log.address.toLowerCase(),
      };
    });

    const erc20PermitInfoTxEvent = createTransactionEvent({
      transaction: {
        hash: erc20PermitInfoTxReceipt.transactionHash,
        from: erc20PermitInfoTxReceipt.from.toLowerCase(),
        to: erc20PermitInfoTxReceipt.to.toLowerCase(),
        nonce: erc20PermitInfoTx.nonce,
        data: erc20PermitInfoTx.data,
        gas: "1",
        gasPrice: erc20PermitInfoTx.gasPrice.toString(),
        value: "0x0",
        r: erc20PermitInfoTx.r,
        s: erc20PermitInfoTx.s,
        v: erc20PermitInfoTx.v.toFixed(),
      },
      block: {
        number: erc20PermitInfoTxReceipt.blockNumber,
        hash: erc20PermitInfoTxReceipt.blockHash,
        timestamp: 1684408535,
      },
      logs: erc20PermitInfoLowerCaseLogs,
      contractAddress: null,
    });

    // ------ ICE-PHISHING-ERC721-APPROVAL-FOR-ALL-INFO ------
    const erc721ApprovalForAllInfoTxReceipt = await realProvider.getTransactionReceipt(
      "0x3cd7ed7da4bf45b0c3ce03ddd0db2c21337e2eb19cf611b7c2b00ef0b47ea48d"
    );

    const erc721ApprovalForAllInfoTx = await realProvider.getTransaction(
      "0x3cd7ed7da4bf45b0c3ce03ddd0db2c21337e2eb19cf611b7c2b00ef0b47ea48d"
    );

    // Lowercase all addresses in logs to match the real txEvent logs
    const erc721ApprovalForAllInfoLowerCaseLogs = erc721ApprovalForAllInfoTxReceipt.logs.map((log) => {
      return {
        ...log,
        address: log.address.toLowerCase(),
      };
    });

    const erc721ApprovalForAllInfoTxEvent = createTransactionEvent({
      transaction: {
        hash: erc721ApprovalForAllInfoTxReceipt.transactionHash,
        from: erc721ApprovalForAllInfoTxReceipt.from.toLowerCase(),
        to: erc721ApprovalForAllInfoTxReceipt.to.toLowerCase(),
        nonce: erc721ApprovalForAllInfoTx.nonce,
        data: erc721ApprovalForAllInfoTx.data,
        gas: "1",
        gasPrice: erc721ApprovalForAllInfoTx.gasPrice.toString(),
        value: "0x0",
        r: erc721ApprovalForAllInfoTx.r,
        s: erc721ApprovalForAllInfoTx.s,
        v: erc721ApprovalForAllInfoTx.v.toFixed(),
      },
      block: {
        number: erc721ApprovalForAllInfoTxReceipt.blockNumber,
        hash: erc721ApprovalForAllInfoTxReceipt.blockHash,
        timestamp: 1684408535,
      },
      logs: erc721ApprovalForAllInfoLowerCaseLogs,
      contractAddress: null,
    });

    // ------ ICE-PHISHING-ERC721-APPROVAL-FOR-ALL ------
    const erc721ApprovalForAllTxReceipt = await realProvider.getTransactionReceipt(
      "0x911ecf2e8cc415bb1b793b8f1a26f1e653656791557cc1774de1e3ca73fa400d"
    );

    const erc721ApprovalForAllTx = await realProvider.getTransaction(
      "0x911ecf2e8cc415bb1b793b8f1a26f1e653656791557cc1774de1e3ca73fa400d"
    );

    // Lowercase all addresses in logs to match the real txEvent logs
    const erc721ApprovalForAllLowerCaseLogs = erc721ApprovalForAllTxReceipt.logs.map((log) => {
      return {
        ...log,
        address: log.address.toLowerCase(),
      };
    });

    const erc721ApprovalForAllTxEvent = createTransactionEvent({
      transaction: {
        hash: erc721ApprovalForAllTxReceipt.transactionHash,
        from: erc721ApprovalForAllTxReceipt.from.toLowerCase(),
        to: erc721ApprovalForAllTxReceipt.to.toLowerCase(),
        nonce: erc721ApprovalForAllTx.nonce,
        data: erc721ApprovalForAllTx.data,
        gas: "1",
        gasPrice: erc721ApprovalForAllTx.gasPrice.toString(),
        value: "0x0",
        r: erc721ApprovalForAllTx.r,
        s: erc721ApprovalForAllTx.s,
        v: erc721ApprovalForAllTx.v.toFixed(),
      },
      block: {
        number: erc721ApprovalForAllTxReceipt.blockNumber,
        hash: erc721ApprovalForAllTxReceipt.blockHash,
        timestamp: 1684408535,
      },
      logs: erc721ApprovalForAllLowerCaseLogs,
      contractAddress: null,
    });

    // ------ ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL-INFO ------
    const erc1155ApprovalForAllInfoTxReceipt = await realProvider.getTransactionReceipt(
      "0x1379930ae672fb59caaf8c2039f907e45b9af9d592852360150b8df39c03af9f"
    );

    const erc1155ApprovalForAllInfoTx = await realProvider.getTransaction(
      "0x1379930ae672fb59caaf8c2039f907e45b9af9d592852360150b8df39c03af9f"
    );

    // Lowercase all addresses in logs to match the real txEvent logs
    const erc1155ApprovalForAllInfoLowerCaseLogs = erc1155ApprovalForAllInfoTxReceipt.logs.map((log) => {
      return {
        ...log,
        address: log.address.toLowerCase(),
      };
    });

    const erc1155ApprovalForAllInfoTxEvent = createTransactionEvent({
      transaction: {
        hash: erc1155ApprovalForAllInfoTxReceipt.transactionHash,
        from: erc1155ApprovalForAllInfoTxReceipt.from.toLowerCase(),
        to: erc1155ApprovalForAllInfoTxReceipt.to.toLowerCase(),
        nonce: erc1155ApprovalForAllInfoTx.nonce,
        data: erc1155ApprovalForAllInfoTx.data,
        gas: "1",
        gasPrice: erc1155ApprovalForAllInfoTx.gasPrice.toString(),
        value: "0x0",
        r: erc1155ApprovalForAllInfoTx.r,
        s: erc1155ApprovalForAllInfoTx.s,
        v: erc1155ApprovalForAllInfoTx.v.toFixed(),
      },
      block: {
        number: erc1155ApprovalForAllInfoTxReceipt.blockNumber,
        hash: erc1155ApprovalForAllInfoTxReceipt.blockHash,
        timestamp: 1684408535,
      },
      logs: erc1155ApprovalForAllInfoLowerCaseLogs,
      contractAddress: null,
    });

    // ------ ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL ------
    const erc1155ApprovalForAllTxReceipt = await realProvider.getTransactionReceipt(
      "0xc3b3bf3fad882aab60c76cfc03c7a776070e81cbdca4281fbdcd9fc5d79b3520"
    );

    const erc1155ApprovalForAllTx = await realProvider.getTransaction(
      "0xc3b3bf3fad882aab60c76cfc03c7a776070e81cbdca4281fbdcd9fc5d79b3520"
    );

    // Lowercase all addresses in logs to match the real txEvent logs
    const erc1155ApprovalForAllLowerCaseLogs = erc1155ApprovalForAllTxReceipt.logs.map((log) => {
      return {
        ...log,
        address: log.address.toLowerCase(),
      };
    });

    const erc1155ApprovalForAllTxEvent = createTransactionEvent({
      transaction: {
        hash: erc1155ApprovalForAllTxReceipt.transactionHash,
        from: erc1155ApprovalForAllTxReceipt.from.toLowerCase(),
        to: erc1155ApprovalForAllTxReceipt.to.toLowerCase(),
        nonce: erc1155ApprovalForAllTx.nonce,
        data: erc1155ApprovalForAllTx.data,
        gas: "1",
        gasPrice: erc1155ApprovalForAllTx.gasPrice.toString(),
        value: "0x0",
        r: erc1155ApprovalForAllTx.r,
        s: erc1155ApprovalForAllTx.s,
        v: erc1155ApprovalForAllTx.v.toFixed(),
      },
      block: {
        number: erc1155ApprovalForAllTxReceipt.blockNumber,
        hash: erc1155ApprovalForAllTxReceipt.blockHash,
        timestamp: 1684408535,
      },
      logs: erc1155ApprovalForAllLowerCaseLogs,
      contractAddress: null,
    });

    // ------ ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS-LOW ------
    const highNumApprovedTransfersLowTxReceipt = await realProvider.getTransactionReceipt(
      "0x2c2cea42ba4f9333035eecb85c1f8fa9e91da069084478c2e634f552594e590c"
    );

    const highNumApprovedTransfersLowTx = await realProvider.getTransaction(
      "0x2c2cea42ba4f9333035eecb85c1f8fa9e91da069084478c2e634f552594e590c"
    );

    // Lowercase all addresses in logs to match the real txEvent logs
    const highNumApprovedTransfersLowLowerCaseLogs = highNumApprovedTransfersLowTxReceipt.logs.map((log) => {
      return {
        ...log,
        address: log.address.toLowerCase(),
      };
    });

    const highNumApprovedTransfersLowTxEvent = createTransactionEvent({
      transaction: {
        hash: highNumApprovedTransfersLowTxReceipt.transactionHash,
        from: highNumApprovedTransfersLowTxReceipt.from.toLowerCase(),
        to: highNumApprovedTransfersLowTxReceipt.to.toLowerCase(),
        nonce: highNumApprovedTransfersLowTx.nonce,
        data: highNumApprovedTransfersLowTx.data,
        gas: "1",
        gasPrice: highNumApprovedTransfersLowTx.gasPrice.toString(),
        value: "0x0",
        r: highNumApprovedTransfersLowTx.r,
        s: highNumApprovedTransfersLowTx.s,
        v: highNumApprovedTransfersLowTx.v.toFixed(),
      },
      block: {
        number: highNumApprovedTransfersLowTxReceipt.blockNumber,
        hash: highNumApprovedTransfersLowTxReceipt.blockHash,
        timestamp: 1685571203,
      },
      logs: highNumApprovedTransfersLowLowerCaseLogs,
      contractAddress: null,
    });

    // ------ ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS ------
    const highNumApprovedTransfersTxReceipt = await realProvider.getTransactionReceipt(
      "0x359a5b3931a21abcb52cd2ee302eb4af472efc3038dae03050aebf89682c4641"
    );

    const highNumApprovedTransfersTx = await realProvider.getTransaction(
      "0x359a5b3931a21abcb52cd2ee302eb4af472efc3038dae03050aebf89682c4641"
    );

    // Lowercase all addresses in logs to match the real txEvent logs
    const highNumApprovedTransfersLowerCaseLogs = highNumApprovedTransfersTxReceipt.logs.map((log) => {
      return {
        ...log,
        address: log.address.toLowerCase(),
      };
    });

    const highNumApprovedTransfersTxEvent = createTransactionEvent({
      transaction: {
        hash: highNumApprovedTransfersTxReceipt.transactionHash,
        from: highNumApprovedTransfersTxReceipt.from.toLowerCase(),
        to: highNumApprovedTransfersTxReceipt.to.toLowerCase(),
        nonce: highNumApprovedTransfersTx.nonce,
        data: highNumApprovedTransfersTx.data,
        gas: "1",
        gasPrice: highNumApprovedTransfersTx.gasPrice.toString(),
        value: "0x0",
        r: highNumApprovedTransfersTx.r,
        s: highNumApprovedTransfersTx.s,
        v: highNumApprovedTransfersTx.v.toFixed(),
      },
      block: {
        number: highNumApprovedTransfersTxReceipt.blockNumber,
        hash: highNumApprovedTransfersTxReceipt.blockHash,
        timestamp: 1685506355,
      },
      logs: highNumApprovedTransfersLowerCaseLogs,
      contractAddress: null,
    });

    // ------ ICE-PHISHING-SUSPICIOUS-APPROVAL ------
    const suspiciousApprovalTxReceipt = await realProvider.getTransactionReceipt(
      "0x68148ff74dce0441d3f5bb0f3f89caa0fe4e906c3f313ecea80ef4584c0288e8"
    );

    const suspiciousApprovalTx = await realProvider.getTransaction(
      "0x68148ff74dce0441d3f5bb0f3f89caa0fe4e906c3f313ecea80ef4584c0288e8"
    );

    // Lowercase all addresses in logs to match the real txEvent logs
    const suspiciousApprovalLowerCaseLogs = suspiciousApprovalTxReceipt.logs.map((log) => {
      return {
        ...log,
        address: log.address.toLowerCase(),
      };
    });

    const suspiciousApprovalTxEvent = createTransactionEvent({
      transaction: {
        hash: suspiciousApprovalTxReceipt.transactionHash,
        from: suspiciousApprovalTxReceipt.from.toLowerCase(),
        to: suspiciousApprovalTxReceipt.to.toLowerCase(),
        nonce: suspiciousApprovalTx.nonce,
        data: suspiciousApprovalTx.data,
        gas: "1",
        gasPrice: suspiciousApprovalTx.gasPrice.toString(),
        value: "0x0",
        r: suspiciousApprovalTx.r,
        s: suspiciousApprovalTx.s,
        v: suspiciousApprovalTx.v.toFixed(),
      },
      block: {
        number: suspiciousApprovalTxReceipt.blockNumber,
        hash: suspiciousApprovalTxReceipt.blockHash,
        timestamp: 1684408535,
      },
      logs: suspiciousApprovalLowerCaseLogs,
      contractAddress: null,
    });
    const suspiciousApprovalBlock = await realProvider.getBlock(suspiciousApprovalTxEvent.block.number);
    const suspiciousApprovalBlockEvent = createBlockEvent({ block: suspiciousApprovalBlock });

    // ------ ICE-PHISHING-ERC20-SUSPICIOUS-PERMIT ------
    const suspiciousPermitTxReceipt = await realProvider.getTransactionReceipt(
      "0xd5faa19239ea4393e7ac432cf7992e36a1b017ed693073b21e98a7a7345d459b"
    );

    const suspiciousPermitTx = await realProvider.getTransaction(
      "0xd5faa19239ea4393e7ac432cf7992e36a1b017ed693073b21e98a7a7345d459b"
    );

    // Lowercase all addresses in logs to match the real txEvent logs
    const suspiciousPermitLowerCaseLogs = suspiciousPermitTxReceipt.logs.map((log) => {
      return {
        ...log,
        address: log.address.toLowerCase(),
      };
    });

    const suspiciousPermitTxEvent = createTransactionEvent({
      transaction: {
        hash: suspiciousPermitTxReceipt.transactionHash,
        from: suspiciousPermitTxReceipt.from.toLowerCase(),
        to: suspiciousPermitTxReceipt.to.toLowerCase(),
        nonce: suspiciousPermitTx.nonce,
        data: suspiciousPermitTx.data,
        gas: "1",
        gasPrice: suspiciousPermitTx.gasPrice.toString(),
        value: "0x0",
        r: suspiciousPermitTx.r,
        s: suspiciousPermitTx.s,
        v: suspiciousPermitTx.v.toFixed(),
      },
      block: {
        number: suspiciousPermitTxReceipt.blockNumber,
        hash: suspiciousPermitTxReceipt.blockHash,
        timestamp: 1684408535,
      },
      logs: suspiciousPermitLowerCaseLogs,
      contractAddress: null,
    });
    const suspiciousPermitBlock = await realProvider.getBlock(suspiciousPermitTxEvent.block.number);
    const suspiciousPermitBlockEvent = createBlockEvent({ block: suspiciousPermitBlock });

    // ------ ICE-PHISHING-SUSPICIOUS-TRANSFER ------
    const suspiciousTransferTxReceipt = await realProvider.getTransactionReceipt(
      "0x20368a87ad7916c2b64d8d1a2c410897297fdb75a530083fb3e30ce0fd1f946b"
    );

    const suspiciousTransferTx = await realProvider.getTransaction(
      "0x20368a87ad7916c2b64d8d1a2c410897297fdb75a530083fb3e30ce0fd1f946b"
    );

    // Lowercase all addresses in logs to match the real txEvent logs
    const suspiciousTransferLowerCaseLogs = suspiciousTransferTxReceipt.logs.map((log) => {
      return {
        ...log,
        address: log.address.toLowerCase(),
      };
    });

    const suspiciousTransferTxEvent = createTransactionEvent({
      transaction: {
        hash: suspiciousTransferTxReceipt.transactionHash,
        from: suspiciousTransferTxReceipt.from.toLowerCase(),
        to: suspiciousTransferTxReceipt.to.toLowerCase(),
        nonce: suspiciousTransferTx.nonce,
        data: suspiciousTransferTx.data,
        gas: "1",
        gasPrice: suspiciousTransferTx.gasPrice.toString(),
        value: "0x0",
        r: suspiciousTransferTx.r,
        s: suspiciousTransferTx.s,
        v: suspiciousTransferTx.v.toFixed(),
      },
      block: {
        number: suspiciousTransferTxReceipt.blockNumber,
        hash: suspiciousTransferTxReceipt.blockHash,
        timestamp: 1684408535,
      },
      logs: suspiciousTransferLowerCaseLogs,
      contractAddress: null,
    });
    const suspiciousTransferBlock = await realProvider.getBlock(suspiciousTransferTxEvent.block.number);
    const suspiciousTransferBlockEvent = createBlockEvent({ block: suspiciousTransferBlock });

    // ------ ICE-PHISHING-SCAM-APPROVAL ------
    const scamApprovalTxReceipt = await realProvider.getTransactionReceipt(
      "0xa2b3580ac99911442b2f854c3d0ab46e04a1843b9e6036739931b8bd3addc37c"
    );

    const scamApprovalTx = await realProvider.getTransaction(
      "0xa2b3580ac99911442b2f854c3d0ab46e04a1843b9e6036739931b8bd3addc37c"
    );

    // Lowercase all addresses in logs to match the real txEvent logs
    const scamApprovalLowerCaseLogs = scamApprovalTxReceipt.logs.map((log) => {
      return {
        ...log,
        address: log.address.toLowerCase(),
      };
    });

    const scamApprovalTxEvent = createTransactionEvent({
      transaction: {
        hash: scamApprovalTxReceipt.transactionHash,
        from: scamApprovalTxReceipt.from.toLowerCase(),
        to: scamApprovalTxReceipt.to.toLowerCase(),
        nonce: scamApprovalTx.nonce,
        data: scamApprovalTx.data,
        gas: "1",
        gasPrice: scamApprovalTx.gasPrice.toString(),
        value: "0x0",
        r: scamApprovalTx.r,
        s: scamApprovalTx.s,
        v: scamApprovalTx.v.toFixed(),
      },
      block: {
        number: scamApprovalTxReceipt.blockNumber,
        hash: scamApprovalTxReceipt.blockHash,
        timestamp: 1684408535,
      },
      logs: scamApprovalLowerCaseLogs,
      contractAddress: null,
    });

    const scamBlock = await realProvider.getBlock(scamApprovalTxEvent.block.number);
    const scamBlockEvent = createBlockEvent({ block: scamBlock });

    // ------ ICE-PHISHING-SCAM-TRANSFER ------
    const scamTransferTxReceipt = await realProvider.getTransactionReceipt(
      "0x9f232273fe3bfe1967b22a9d0ae5edc765d374677d857b33566a72b07cdb26f0"
    );

    const scamTransferTx = await realProvider.getTransaction(
      "0x9f232273fe3bfe1967b22a9d0ae5edc765d374677d857b33566a72b07cdb26f0"
    );

    // Lowercase all addresses in logs to match the real txEvent logs
    const scamTransferLowerCaseLogs = scamTransferTxReceipt.logs.map((log) => {
      return {
        ...log,
        address: log.address.toLowerCase(),
      };
    });

    const scamTransferTxEvent = createTransactionEvent({
      transaction: {
        hash: scamTransferTxReceipt.transactionHash,
        from: scamTransferTxReceipt.from.toLowerCase(),
        to: scamTransferTxReceipt.to.toLowerCase(),
        nonce: scamTransferTx.nonce,
        data: scamTransferTx.data,
        gas: "1",
        gasPrice: scamTransferTx.gasPrice.toString(),
        value: "0x0",
        r: scamTransferTx.r,
        s: scamTransferTx.s,
        v: scamTransferTx.v.toFixed(),
      },
      block: {
        number: scamTransferTxReceipt.blockNumber,
        hash: scamTransferTxReceipt.blockHash,
        timestamp: 1684408535,
      },
      logs: scamTransferLowerCaseLogs,
      contractAddress: null,
    });

    // ------ ICE-PHISHING-PULL-SWEEPTOKEN ------
    const pullSweepTokenTxReceipt = await realProvider.getTransactionReceipt(
      "0x352bd38c83b283f069526726e277481e48f6ca8addd55e91def4ae9724a10057"
    );

    const pullSweepTokenTx = await realProvider.getTransaction(
      "0x352bd38c83b283f069526726e277481e48f6ca8addd55e91def4ae9724a10057"
    );

    // Lowercase all addresses in logs to match the real txEvent logs
    const pullSweepTokenLowerCaseLogs = pullSweepTokenTxReceipt.logs.map((log) => {
      return {
        ...log,
        address: log.address.toLowerCase(),
      };
    });

    const pullSweepTokenTxEvent = createTransactionEvent({
      transaction: {
        hash: pullSweepTokenTxReceipt.transactionHash,
        from: pullSweepTokenTxReceipt.from.toLowerCase(),
        to: pullSweepTokenTxReceipt.to.toLowerCase(),
        nonce: pullSweepTokenTx.nonce,
        data: pullSweepTokenTx.data,
        gas: "1",
        gasPrice: pullSweepTokenTx.gasPrice.toString(),
        value: "0x0",
        r: pullSweepTokenTx.r,
        s: pullSweepTokenTx.s,
        v: pullSweepTokenTx.v.toFixed(),
      },
      traces: [
        {
          action: {
            callType: "call",
            to: "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",
            input:
              "0xac9650d800000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000044f2d5d56b000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000127d0138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000064df2ab5bb000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000127d0138000000000000000000000000b6af46be91b1ba4043c99f968c18871d3a76305900000000000000000000000000000000000000000000000000000000",
            from: "0x62e97ed3abef3cd96f78b3c7ac96f001d40bb61c",
            value: "0x0",
            init: undefined,
            address: undefined,
            balance: undefined,
            refundAddress: undefined,
          },
          blockHash: "0xaa6be1416e73bada1afbf0d6eb2c5342fe25f43a30618a5b8368a0ac1128779e",
          blockNumber: 16394585,
          result: {
            gasUsed: "0x117ae",
            address: undefined,
            code: undefined,
            output:
              "0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
          },
          subtraces: 2,
          traceAddress: [],
          transactionHash: "0x352bd38c83b283f069526726e277481e48f6ca8addd55e91def4ae9724a10057",
          transactionPosition: 25,
          type: "call",
          error: undefined,
        },
        {
          action: {
            callType: "delegatecall",
            to: "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",
            input:
              "0xf2d5d56b000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000127d0138",
            from: "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",
            value: "0x0",
            init: undefined,
            address: undefined,
            balance: undefined,
            refundAddress: undefined,
          },
          blockHash: "0xaa6be1416e73bada1afbf0d6eb2c5342fe25f43a30618a5b8368a0ac1128779e",
          blockNumber: 16394585,
          result: {
            gasUsed: "0xd299",
            address: undefined,
            code: undefined,
            output: "0x",
          },
          subtraces: 1,
          traceAddress: [0],
          transactionHash: "0x352bd38c83b283f069526726e277481e48f6ca8addd55e91def4ae9724a10057",
          transactionPosition: 25,
          type: "call",
          error: undefined,
        },
        {
          action: {
            callType: "call",
            to: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            input:
              "0x23b872dd00000000000000000000000062e97ed3abef3cd96f78b3c7ac96f001d40bb61c00000000000000000000000068b3465833fb72a70ecdf485e0e4c7bd8665fc4500000000000000000000000000000000000000000000000000000000127d0138",
            from: "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",
            value: "0x0",
            init: undefined,
            address: undefined,
            balance: undefined,
            refundAddress: undefined,
          },
          blockHash: "0xaa6be1416e73bada1afbf0d6eb2c5342fe25f43a30618a5b8368a0ac1128779e",
          blockNumber: 16394585,
          result: {
            gasUsed: "0xc348",
            address: undefined,
            code: undefined,
            output: "0x0000000000000000000000000000000000000000000000000000000000000001",
          },
          subtraces: 1,
          traceAddress: [0, 0],
          transactionHash: "0x352bd38c83b283f069526726e277481e48f6ca8addd55e91def4ae9724a10057",
          transactionPosition: 25,
          type: "call",
          error: undefined,
        },
        {
          action: {
            callType: "delegatecall",
            to: "0xa2327a938febf5fec13bacfb16ae10ecbc4cbdcf",
            input:
              "0x23b872dd00000000000000000000000062e97ed3abef3cd96f78b3c7ac96f001d40bb61c00000000000000000000000068b3465833fb72a70ecdf485e0e4c7bd8665fc4500000000000000000000000000000000000000000000000000000000127d0138",
            from: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            value: "0x0",
            init: undefined,
            address: undefined,
            balance: undefined,
            refundAddress: undefined,
          },
          blockHash: "0xaa6be1416e73bada1afbf0d6eb2c5342fe25f43a30618a5b8368a0ac1128779e",
          blockNumber: 16394585,
          result: {
            gasUsed: "0xa6c9",
            address: undefined,
            code: undefined,
            output: "0x0000000000000000000000000000000000000000000000000000000000000001",
          },
          subtraces: 0,
          traceAddress: [0, 0, 0],
          transactionHash: "0x352bd38c83b283f069526726e277481e48f6ca8addd55e91def4ae9724a10057",
          transactionPosition: 25,
          type: "call",
          error: undefined,
        },
        {
          action: {
            callType: "delegatecall",
            to: "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",
            input:
              "0xdf2ab5bb000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000127d0138000000000000000000000000b6af46be91b1ba4043c99f968c18871d3a763059",
            from: "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",
            value: "0x0",
            init: undefined,
            address: undefined,
            balance: undefined,
            refundAddress: undefined,
          },
          blockHash: "0xaa6be1416e73bada1afbf0d6eb2c5342fe25f43a30618a5b8368a0ac1128779e",
          blockNumber: 16394585,
          result: {
            gasUsed: "0x39df",
            address: undefined,
            code: undefined,
            output: "0x",
          },
          subtraces: 2,
          traceAddress: [1],
          transactionHash: "0x352bd38c83b283f069526726e277481e48f6ca8addd55e91def4ae9724a10057",
          transactionPosition: 25,
          type: "call",
          error: undefined,
        },
        {
          action: {
            callType: "staticcall",
            to: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            input: "0x70a0823100000000000000000000000068b3465833fb72a70ecdf485e0e4c7bd8665fc45",
            from: "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",
            value: "0x0",
            init: undefined,
            address: undefined,
            balance: undefined,
            refundAddress: undefined,
          },
          blockHash: "0xaa6be1416e73bada1afbf0d6eb2c5342fe25f43a30618a5b8368a0ac1128779e",
          blockNumber: 16394585,
          result: {
            gasUsed: "0x523",
            address: undefined,
            code: undefined,
            output: "0x00000000000000000000000000000000000000000000000000000000127d0138",
          },
          subtraces: 1,
          traceAddress: [1, 0],
          transactionHash: "0x352bd38c83b283f069526726e277481e48f6ca8addd55e91def4ae9724a10057",
          transactionPosition: 25,
          type: "call",
          error: undefined,
        },
        {
          action: {
            callType: "delegatecall",
            to: "0xa2327a938febf5fec13bacfb16ae10ecbc4cbdcf",
            input: "0x70a0823100000000000000000000000068b3465833fb72a70ecdf485e0e4c7bd8665fc45",
            from: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            value: "0x0",
            init: undefined,
            address: undefined,
            balance: undefined,
            refundAddress: undefined,
          },
          blockHash: "0xaa6be1416e73bada1afbf0d6eb2c5342fe25f43a30618a5b8368a0ac1128779e",
          blockNumber: 16394585,
          result: {
            gasUsed: "0x211",
            address: undefined,
            code: undefined,
            output: "0x00000000000000000000000000000000000000000000000000000000127d0138",
          },
          subtraces: 0,
          traceAddress: [1, 0, 0],
          transactionHash: "0x352bd38c83b283f069526726e277481e48f6ca8addd55e91def4ae9724a10057",
          transactionPosition: 25,
          type: "call",
          error: undefined,
        },
        {
          action: {
            callType: "call",
            to: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            input:
              "0xa9059cbb000000000000000000000000b6af46be91b1ba4043c99f968c18871d3a76305900000000000000000000000000000000000000000000000000000000127d0138",
            from: "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",
            value: "0x0",
            init: undefined,
            address: undefined,
            balance: undefined,
            refundAddress: undefined,
          },
          blockHash: "0xaa6be1416e73bada1afbf0d6eb2c5342fe25f43a30618a5b8368a0ac1128779e",
          blockNumber: 16394585,
          result: {
            gasUsed: "0x2d61",
            address: undefined,
            code: undefined,
            output: "0x0000000000000000000000000000000000000000000000000000000000000001",
          },
          subtraces: 1,
          traceAddress: [1, 1],
          transactionHash: "0x352bd38c83b283f069526726e277481e48f6ca8addd55e91def4ae9724a10057",
          transactionPosition: 25,
          type: "call",
          error: undefined,
        },
        {
          action: {
            callType: "delegatecall",
            to: "0xa2327a938febf5fec13bacfb16ae10ecbc4cbdcf",
            input:
              "0xa9059cbb000000000000000000000000b6af46be91b1ba4043c99f968c18871d3a76305900000000000000000000000000000000000000000000000000000000127d0138",
            from: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            value: "0x0",
            init: undefined,
            address: undefined,
            balance: undefined,
            refundAddress: undefined,
          },
          blockHash: "0xaa6be1416e73bada1afbf0d6eb2c5342fe25f43a30618a5b8368a0ac1128779e",
          blockNumber: 16394585,
          result: {
            gasUsed: "0x2a4c",
            address: undefined,
            code: undefined,
            output: "0x0000000000000000000000000000000000000000000000000000000000000001",
          },
          subtraces: 0,
          traceAddress: [1, 1, 0],
          transactionHash: "0x352bd38c83b283f069526726e277481e48f6ca8addd55e91def4ae9724a10057",
          transactionPosition: 25,
          type: "call",
          error: undefined,
        },
      ],
      block: {
        number: pullSweepTokenTxReceipt.blockNumber,
        hash: pullSweepTokenTxReceipt.blockHash,
        timestamp: 1684408535,
      },
      logs: pullSweepTokenLowerCaseLogs,
      contractAddress: null,
    });

    // ------ ICE-PHISHING-OPENSEA-PROXY-UPGRADE ------
    const openseaProxyUpgradeTxReceipt = await realProvider.getTransactionReceipt(
      "0x938363b2496d08b7e06b0c306b38def5d619817a5f972fc8076835b6781c5ae2"
    );

    const openseaProxyUpgradeTx = await realProvider.getTransaction(
      "0x938363b2496d08b7e06b0c306b38def5d619817a5f972fc8076835b6781c5ae2"
    );

    // Lowercase all addresses in logs to match the real txEvent logs
    const openseaProxyUpgradeLowerCaseLogs = openseaProxyUpgradeTxReceipt.logs.map((log) => {
      return {
        ...log,
        address: log.address.toLowerCase(),
      };
    });

    const openseaProxyUpgradeTxEvent = createTransactionEvent({
      transaction: {
        hash: openseaProxyUpgradeTxReceipt.transactionHash,
        from: openseaProxyUpgradeTxReceipt.from.toLowerCase(),
        to: openseaProxyUpgradeTxReceipt.to.toLowerCase(),
        nonce: openseaProxyUpgradeTx.nonce,
        data: openseaProxyUpgradeTx.data,
        gas: "1",
        gasPrice: openseaProxyUpgradeTx.gasPrice.toString(),
        value: "0x0",
        r: openseaProxyUpgradeTx.r,
        s: openseaProxyUpgradeTx.s,
        v: openseaProxyUpgradeTx.v.toFixed(),
      },
      block: {
        number: openseaProxyUpgradeTxReceipt.blockNumber,
        hash: openseaProxyUpgradeTxReceipt.blockHash,
        timestamp: 1684408535,
      },
      logs: openseaProxyUpgradeLowerCaseLogs,
      contractAddress: null,
    });

    // ------ ICE-PHISHING-ERC20-SCAM-PERMIT ------
    const scamPermitTxReceipt = await realProvider.getTransactionReceipt(
      "0x3765954bcbba3ea152167a92daa5f6953f6dc27db28e68d14138d8767ebdacd9"
    );

    const scamPermitTx = await realProvider.getTransaction(
      "0x3765954bcbba3ea152167a92daa5f6953f6dc27db28e68d14138d8767ebdacd9"
    );

    // Lowercase all addresses in logs to match the real txEvent logs
    const scamPermitLowerCaseLogs = scamPermitTxReceipt.logs.map((log) => {
      return {
        ...log,
        address: log.address.toLowerCase(),
      };
    });

    const scamPermitTxEvent = createTransactionEvent({
      transaction: {
        hash: scamPermitTxReceipt.transactionHash,
        from: scamPermitTxReceipt.from.toLowerCase(),
        to: scamPermitTxReceipt.to.toLowerCase(),
        nonce: scamPermitTx.nonce,
        data: scamPermitTx.data,
        gas: "1",
        gasPrice: scamPermitTx.gasPrice.toString(),
        value: "0x0",
        r: scamPermitTx.r,
        s: scamPermitTx.s,
        v: scamPermitTx.v.toFixed(),
      },
      block: {
        number: scamPermitTxReceipt.blockNumber,
        hash: scamPermitTxReceipt.blockHash,
        timestamp: 1684408535,
      },
      logs: scamPermitLowerCaseLogs,
      contractAddress: null,
    });

    // ------ ICE-PHISHING-SCAM-CREATOR-APPROVAL ------
    const scamCreatorApprovalTxReceipt = await realProvider.getTransactionReceipt(
      "0xfddb6019978a939d6e3f678ec7fb0d433c9352bc2b49a538e722b1b9e63eddf7"
    );

    const scamCreatorApprovalTx = await realProvider.getTransaction(
      "0xfddb6019978a939d6e3f678ec7fb0d433c9352bc2b49a538e722b1b9e63eddf7"
    );

    // Lowercase all addresses in logs to match the real txEvent logs
    const scamCreatorApprovalLowerCaseLogs = scamCreatorApprovalTxReceipt.logs.map((log) => {
      return {
        ...log,
        address: log.address.toLowerCase(),
      };
    });

    const scamCreatorApprovalTxEvent = createTransactionEvent({
      transaction: {
        hash: scamCreatorApprovalTxReceipt.transactionHash,
        from: scamCreatorApprovalTxReceipt.from.toLowerCase(),
        to: scamCreatorApprovalTxReceipt.to.toLowerCase(),
        nonce: scamCreatorApprovalTx.nonce,
        data: scamCreatorApprovalTx.data,
        gas: "1",
        gasPrice: scamCreatorApprovalTx.gasPrice.toString(),
        value: "0x0",
        r: scamCreatorApprovalTx.r,
        s: scamCreatorApprovalTx.s,
        v: scamCreatorApprovalTx.v.toFixed(),
      },
      block: {
        number: scamCreatorApprovalTxReceipt.blockNumber,
        hash: scamCreatorApprovalTxReceipt.blockHash,
        timestamp: 1684408535,
      },
      logs: scamCreatorApprovalLowerCaseLogs,
      contractAddress: null,
    });

    let totalTimeNormalTx = 0;
    let totalTimeErc20ApprovalsInfo = 0;
    let totalTimeErc20Approvals = 0;
    let totalTimeErc721ApprovalsInfo = 0;
    let totalTimeErc721Approvals = 0;
    let totalTimeErc20PermitInfo = 0;
    let totalTimeErc20Permit = 0;
    let totalTimeErc721ApprovalForAllInfo = 0;
    let totalTimeErc721ApprovalForAll = 0;
    let totalTimeErc1155ApprovalForAllInfo = 0;
    let totalTimeErc1155ApprovalForAll = 0;
    let totalTimeHighNumApprovedTransfersLow = 0;
    let totalTimeHighNumApprovedTransfers = 0;
    let totalTimeSuspiciousApproval = 0;
    let totalTimeSuspiciousPermit = 0;
    let totalTimeSuspiciousTransfer = 0;
    let totalTimeScamApproval = 0;
    let totalTimeScamTransfer = 0;
    let totalTimePullSweepToken = 0;
    let totalTimeOpenseaProxyUpgrade = 0;
    let totalTimeScamPermit = 0;
    let totalTimeScamCreatorApproval = 0;

    for (let i = 0; i < blocksToRun; i++) {
      const startTimeNormalTx = performance.now();
      await handleTransaction(normalTxEvent);
      const endTimeNormalTx = performance.now();
      totalTimeNormalTx += endTimeNormalTx - startTimeNormalTx;

      const startTimeErc20ApprovalsInfo = performance.now();
      await handleTransaction(erc20ApprovalsInfoTxEvent);
      const endTimeErc20ApprovalsInfo = performance.now();
      totalTimeErc20ApprovalsInfo += endTimeErc20ApprovalsInfo - startTimeErc20ApprovalsInfo;

      const startTimeErc20Approvals = performance.now();
      await handleTransaction(erc20ApprovalsTxEvent);
      const endTimeErc20Approvals = performance.now();
      totalTimeErc20Approvals += endTimeErc20Approvals - startTimeErc20Approvals;

      const startTimeErc721ApprovalsInfo = performance.now();
      await handleTransaction(erc721ApprovalsInfoTxEvent);
      const endTimeErc721ApprovalsInfo = performance.now();
      totalTimeErc721ApprovalsInfo += endTimeErc721ApprovalsInfo - startTimeErc721ApprovalsInfo;

      const startTimeErc721Approvals = performance.now();
      await handleTransaction(erc721ApprovalsTxEvent);
      const endTimeErc721Approvals = performance.now();
      totalTimeErc721Approvals += endTimeErc721Approvals - startTimeErc721Approvals;

      const startTimeErc20PermitInfo = performance.now();
      await handleTransaction(erc20PermitInfoTxEvent);
      const endTimeErc20PermitInfo = performance.now();
      totalTimeErc20PermitInfo += endTimeErc20PermitInfo - startTimeErc20PermitInfo;

      const startTimeErc20Permit = performance.now();
      await handleTransaction(erc20PermitTxEvent);
      const endTimeErc20Permit = performance.now();
      totalTimeErc20Permit += endTimeErc20Permit - startTimeErc20Permit;

      const startTimeErc721ApprovalForAllInfo = performance.now();
      await handleTransaction(erc721ApprovalForAllInfoTxEvent);
      const endTimeErc721ApprovalForAllInfo = performance.now();
      totalTimeErc721ApprovalForAllInfo += endTimeErc721ApprovalForAllInfo - startTimeErc721ApprovalForAllInfo;

      const startTimeErc721ApprovalForAll = performance.now();
      await handleTransaction(erc721ApprovalForAllTxEvent);
      const endTimeErc721ApprovalForAll = performance.now();
      totalTimeErc721ApprovalForAll += endTimeErc721ApprovalForAll - startTimeErc721ApprovalForAll;

      const startTimeErc1155ApprovalForAllInfo = performance.now();
      await handleTransaction(erc1155ApprovalForAllInfoTxEvent);
      const endTimeErc1155ApprovalForAllInfo = performance.now();
      totalTimeErc1155ApprovalForAllInfo += endTimeErc1155ApprovalForAllInfo - startTimeErc1155ApprovalForAllInfo;

      const startTimeErc1155ApprovalForAll = performance.now();
      await handleTransaction(erc1155ApprovalForAllTxEvent);
      const endTimeErc1155ApprovalForAll = performance.now();
      totalTimeErc1155ApprovalForAll += endTimeErc1155ApprovalForAll - startTimeErc1155ApprovalForAll;

      const startTimeHighNumApprovedTransfersLow = performance.now();
      await handleTransaction(highNumApprovedTransfersLowTxEvent);
      const endTimeHighNumApprovedTransfersLow = performance.now();
      totalTimeHighNumApprovedTransfersLow += endTimeHighNumApprovedTransfersLow - startTimeHighNumApprovedTransfersLow;

      const startTimeHighNumApprovedTransfers = performance.now();
      await handleTransaction(highNumApprovedTransfersTxEvent);
      const endTimeHighNumApprovedTransfers = performance.now();
      totalTimeHighNumApprovedTransfers += endTimeHighNumApprovedTransfers - startTimeHighNumApprovedTransfers;

      await handleBlock(suspiciousApprovalBlockEvent);
      const startTimeSuspiciousApproval = performance.now();
      await handleTransaction(suspiciousApprovalTxEvent);
      const endTimeSuspiciousApproval = performance.now();
      totalTimeSuspiciousApproval += endTimeSuspiciousApproval - startTimeSuspiciousApproval;

      resetInit();

      await handleBlock(suspiciousTransferBlockEvent);
      const startTimeSuspiciousTransfer = performance.now();
      await handleTransaction(suspiciousTransferTxEvent);
      const endTimeSuspiciousTransfer = performance.now();
      totalTimeSuspiciousTransfer += endTimeSuspiciousTransfer - startTimeSuspiciousTransfer;

      resetInit();

      await handleBlock(suspiciousPermitBlockEvent);
      const startTimeSuspiciousPermit = performance.now();
      await handleTransaction(suspiciousPermitTxEvent);
      const endTimeSuspiciousPermit = performance.now();
      totalTimeSuspiciousPermit += endTimeSuspiciousPermit - startTimeSuspiciousPermit;

      await handleBlock(scamBlockEvent);

      const startTimeScamApproval = performance.now();
      await handleTransaction(scamApprovalTxEvent);
      const endTimeScamApproval = performance.now();
      totalTimeScamApproval += endTimeScamApproval - startTimeScamApproval;

      const startTimeScamTransfer = performance.now();
      await handleTransaction(scamTransferTxEvent);
      const endTimeScamTransfer = performance.now();
      totalTimeScamTransfer += endTimeScamTransfer - startTimeScamTransfer;

      const startTimePullSweepToken = performance.now();
      await handleTransaction(pullSweepTokenTxEvent);
      const endTimePullSweepToken = performance.now();
      totalTimePullSweepToken += endTimePullSweepToken - startTimePullSweepToken;

      const startTimeOpenseaProxyUpgrade = performance.now();
      await handleTransaction(openseaProxyUpgradeTxEvent);
      const endTimeOpenseaProxyUpgrade = performance.now();
      totalTimeOpenseaProxyUpgrade += endTimeOpenseaProxyUpgrade - startTimeOpenseaProxyUpgrade;

      const startTimeScamPermit = performance.now();
      await handleTransaction(scamPermitTxEvent);
      const endTimeScamPermit = performance.now();
      totalTimeScamPermit += endTimeScamPermit - startTimeScamPermit;

      const startTimeScamCreatorApproval = performance.now();
      await handleTransaction(scamCreatorApprovalTxEvent);
      const endTimeScamCreatorApproval = performance.now();
      totalTimeScamCreatorApproval += endTimeScamCreatorApproval - startTimeScamCreatorApproval;
    }

    const processingTimeNormalTx = totalTimeNormalTx / blocksToRun;
    const processingTimeErc20ApprovalsInfo = totalTimeErc20ApprovalsInfo / blocksToRun;
    const processingTimeErc20Approvals = totalTimeErc20Approvals / blocksToRun;
    const processingTimeErc721ApprovalsInfo = totalTimeErc721ApprovalsInfo / blocksToRun;
    const processingTimeErc721Approvals = totalTimeErc721Approvals / blocksToRun;
    const processingTimeErc20PermitInfo = totalTimeErc20PermitInfo / blocksToRun;
    const processingTimeErc20Permit = totalTimeErc20Permit / blocksToRun;
    const processingTimeErc721ApprovalForAllInfo = totalTimeErc721ApprovalForAllInfo / blocksToRun;
    const processingTimeErc721ApprovalForAll = totalTimeErc721ApprovalForAll / blocksToRun;
    const processingTimeErc1155ApprovalForAllInfo = totalTimeErc1155ApprovalForAllInfo / blocksToRun;
    const processingTimeErc1155ApprovalForAll = totalTimeErc1155ApprovalForAll / blocksToRun;
    const processingTimeHighNumApprovedTransfersLow = totalTimeHighNumApprovedTransfersLow / blocksToRun;
    const processingTimeHighNumApprovedTransfers = totalTimeHighNumApprovedTransfers / blocksToRun;
    const processingTimeSuspiciousApproval = totalTimeSuspiciousApproval / blocksToRun;
    const processingTimeSuspiciousPermit = totalTimeSuspiciousPermit / blocksToRun;
    const processingTimeSuspiciousTransfer = totalTimeSuspiciousTransfer / blocksToRun;
    const processingTimeScamApproval = totalTimeScamApproval / blocksToRun;
    const processingTimeScamTransfer = totalTimeScamTransfer / blocksToRun;
    const processingTimePullSweepToken = totalTimePullSweepToken / blocksToRun;
    const processingTimeOpenseaProxyUpgrade = totalTimeOpenseaProxyUpgrade / blocksToRun;
    const processingTimeScamPermit = totalTimeScamPermit / blocksToRun;
    const processingTimeScamCreatorApproval = totalTimeScamCreatorApproval / blocksToRun;

    expect(
      processingTimeNormalTx * 0.65 +
        processingTimeErc20ApprovalsInfo * 0.04 +
        processingTimeErc20Approvals * 0.02 +
        processingTimeErc721ApprovalsInfo * 0.02 +
        processingTimeErc721Approvals * 0.02 +
        processingTimeErc20PermitInfo * 0.02 +
        processingTimeErc20Permit * 0.02 +
        processingTimeErc721ApprovalForAllInfo * 0.02 +
        processingTimeErc721ApprovalForAll * 0.02 +
        processingTimeErc1155ApprovalForAllInfo * 0.02 +
        processingTimeErc1155ApprovalForAll * 0.02 +
        processingTimeHighNumApprovedTransfersLow * 0.02 +
        processingTimeHighNumApprovedTransfers * 0.02 +
        processingTimeSuspiciousApproval * 0.01 +
        processingTimeSuspiciousPermit * 0.01 +
        processingTimeSuspiciousTransfer * 0.01 +
        processingTimeScamApproval * 0.01 +
        processingTimeScamTransfer * 0.01 +
        processingTimePullSweepToken * 0.01 +
        processingTimeOpenseaProxyUpgrade * 0.01 +
        processingTimeScamPermit * 0.01 +
        processingTimeScamCreatorApproval * 0.01
    ).toBeLessThan(1250);
  });
});

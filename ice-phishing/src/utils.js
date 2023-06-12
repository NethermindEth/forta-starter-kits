const { ethers } = require("forta-agent");
const { timePeriodDays } = require("../bot-config.json");

const ONE_DAY = 24 * 60 * 60;
const TIME_PERIOD = timePeriodDays * ONE_DAY;
const ADDRESS_ZERO = ethers.constants.AddressZero;
const MALICIOUS_SMART_CONTRACT_ML_BOT_V2_ID = "0x0b241032ca430d9c02eaa6a52d217bbff046f0d1b3f3d2aa928e42a97150ec91";
const safeBatchTransferFrom1155Sig = "2eb2c2d6";
const MAX_OBJECT_SIZE = 9 * 1024 * 1024; // 9 MB

// Ignore Approvals to Uniswap Permit 2, OpenSea Conduit, Blur Execution Delegate and Uniswap Universal Router
const IGNORED_ADDRESSES = [
  "0x000000000022D473030F116dDEE9F6B43aC78BA3",
  "0x1E0049783F008A0085193E00003D00cd54003c71",
  "0x00000000000111AbE46ff893f3B2fdF1F759a8A8",
  "0xEf1c6E67703c7BD7107eed8303Fbe6EC2554BF6B",
];

const UNISWAP_ROUTER_ADDRESSES = [
  "0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b", // Uniswap Universal Router
  "0xe592427a0aece92de3edee1f18e0157c05861564", // Uniswap V3: Router
  "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45", // Uniswap V3: Router 2
  "0x7a250d5630b4cf539739df2c5dacb4c659f2488d", // Uniswap V2: Router 2
];

const upgradedEventABI = ["event Upgraded(address indexed implementation)"];

const permitFunctionABI =
  "function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) external";

const daiPermitFunctionABI =
  "function permit(address owner, address spender, uint256 nonce, uint256 deadline, bool allowed, uint8 v, bytes32 r, bytes32 s) external";

const uniswapPermitFunctionABI =
  "function permit(address owner, tuple(tuple(address token, uint160 value, uint48 expiration, uint48 nonce) details, address spender, uint256 deadline) permitSingle, bytes calldata signature) external ";

const pullFunctionABI = "function pull(address token, uint256 value) external";
const sweepTokenFunctionABI = "function sweepToken(address token, uint256 amountMinimum, address recipient) external";

const approvalEventErc20ABI = "event Approval(address indexed owner, address indexed spender, uint256 value)";
const approvalEventErc721ABI =
  "event Approval(address indexed owner, address indexed spender, uint256 indexed tokenId)";
const approvalForAllEventABI = "event ApprovalForAll(address indexed owner, address indexed spender, bool approved)";

const transferEventErc20ABI = "event Transfer(address indexed from, address indexed to, uint256 value)";
const transferEventErc721ABI = "event Transfer(address indexed from, address indexed to, uint256 indexed tokenId)";

const erc1155transferEventABI = [
  "event TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 tokenId, uint256 value)",
  "event TransferBatch(address indexed operator, address indexed from, address indexed to, uint256[] tokenIds, uint256[] values)",
];

const ERC_20_721_ABI = ["function balanceOf(address) public view returns (uint256)"];
const ERC_20_721_INTERFACE = new ethers.utils.Interface(ERC_20_721_ABI);

const ERC_1155_ABI = ["function balanceOf(address owner, uint256 id) external view returns (uint256)"];
const ERC_1155_INTERFACE = new ethers.utils.Interface(ERC_1155_ABI);

module.exports = {
  TIME_PERIOD,
  ADDRESS_ZERO,
  MALICIOUS_SMART_CONTRACT_ML_BOT_V2_ID,
  MAX_OBJECT_SIZE,
  IGNORED_ADDRESSES,
  UNISWAP_ROUTER_ADDRESSES,
  safeBatchTransferFrom1155Sig,
  permitFunctionABI,
  daiPermitFunctionABI,
  uniswapPermitFunctionABI,
  pullFunctionABI,
  sweepTokenFunctionABI,
  approvalEventErc20ABI,
  approvalEventErc721ABI,
  approvalForAllEventABI,
  transferEventErc20ABI,
  transferEventErc721ABI,
  erc1155transferEventABI,
  upgradedEventABI,
  ERC_20_721_ABI,
  ERC_20_721_INTERFACE,
  ERC_1155_ABI,
  ERC_1155_INTERFACE,
};

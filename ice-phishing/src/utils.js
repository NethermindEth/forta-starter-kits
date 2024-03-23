const { ethers } = require("forta-agent");
const { timePeriodDays } = require("../bot-config.json");

const ONE_DAY = 24 * 60 * 60;
const TIME_PERIOD = timePeriodDays * ONE_DAY;
const ADDRESS_ZERO = ethers.constants.AddressZero;
const MALICIOUS_SMART_CONTRACT_ML_BOT_V2_ID = "0x0b241032ca430d9c02eaa6a52d217bbff046f0d1b3f3d2aa928e42a97150ec91";
const safeBatchTransferFrom1155Sig = "2eb2c2d6";
const transferFromSig = "0x23b872dd";
const MAX_OBJECT_SIZE = 9 * 1024 * 1024; // 9 MB

const UNISWAP_PERMIT_2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3";

// Ignore Approvals to Uniswap Permit 2, OpenSea Conduit, Blur Execution Delegate and Uniswap Universal Router
const IGNORED_ADDRESSES = [
  UNISWAP_PERMIT_2,
  "0x1E0049783F008A0085193E00003D00cd54003c71",
  "0x00000000000111AbE46ff893f3B2fdF1F759a8A8",
  "0xEf1c6E67703c7BD7107eed8303Fbe6EC2554BF6B",
];

const UNISWAP_ROUTER_ADDRESSES = [
  "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad", // Uniswap Universal Router
  "0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b", // Uniswap Universal Router 2
  "0xe592427a0aece92de3edee1f18e0157c05861564", // Uniswap V3: Router
  "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45", // Uniswap V3: Router 2
  "0x7a250d5630b4cf539739df2c5dacb4c659f2488d", // Uniswap V2: Router 2
];

const STABLECOINS = [
  "0xdac17f958d2ee523a2206206994597c13d831ec7", // USDT
  "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // USDC
];

const CEX_ADDRESSES = [
  "0x3f5ce5fbfe3e9af3971dd833d26ba9b5c936f0be", // Binance
  "0x85b931a32a0725be14285b66f1a22178c672d69b",
  "0x708396f17127c42383e3b9014072679b2f60b82f",
  "0xe0f0cfde7ee664943906f17f7f14342e76a5cec7",
  "0x8f22f2063d253846b53609231ed80fa571bc0c8f",
  "0x28c6c06298d514db089934071355e5743bf21d60",
  "0x21a31ee1afc51d94c2efccaa2092ad1028285549",
  "0xdfd5293d8e347dfe59e90efd55b2956a1343963d",
  "0x56eddb7aa87536c09ccc2793473599fd21a8b17f",
  "0x9696f59e4d72e237be84ffd425dcad154bf96976",
  "0x4d9ff50ef4da947364bb9650892b2554e7be5e2b",
  "0xd551234ae421e3bcba99a0da6d736074f22192ff",
  "0x4976a4a02f38326660d17bf34b431dc6e2eb2327",
  "0xd88b55467f58af508dbfdc597e8ebd2ad2de49b3",
  "0x7dfe9a368b6cf0c0309b763bb8d16da326e8f46e",
  "0x345d8e3a1f62ee6b1d483890976fd66168e390f2",
  "0xc3c8e0a39769e2308869f7461364ca48155d1d9e",
  "0x2e581a5ae722207aa59acd3939771e7c7052dd3d",
  "0x44592b81c05b4c35efb8424eb9d62538b949ebbf",
  "0xa344c7ada83113b3b56941f6e85bf2eb425949f3",
  "0x5a52e96bacdabb82fd05763e25335261b270efcb",
  "0x06a0048079ec6571cd1b537418869cde6191d42d",
  "0x564286362092d8e7936f0549571a803b203aaced",
  "0x892e9e24aea3f27f4c6e9360e312cce93cc98ebe",
  "0x00799bbc833d5b168f0410312d2a8fd9e0e3079c",
  "0x141fef8cd8397a390afe94846c8bd6f4ab981c48",
  "0x50d669f43b484166680ecc3670e4766cdb0945ce",
  "0x2f7e209e0f5f645c7612d7610193fe268f118b28",
  "0xd9d93951896b4ef97d251334ef2a0e39f6f6d7d7",
  "0x19184ab45c40c2920b0e0e31413b9434abd243ed",
  "0x0681d8db095565fe8a346fa0277bffde9c0edbbf",
  "0x294b9b133ca7bc8ed2cdd03ba661a4c6d3a834d9",
  "0x5d7f34372fa8708e09689d400a613eee67f75543",
  "0xfe9e8709d3215310075d67e3ed32a380ccf451c8",
  "0x4e9ce36e442e55ecd9025b9a6e0d88485d628a67",
  "0xbe0eb53f46cd790cd13851d5eff43d12404d33e8",
  "0xf977814e90da44bfa03b6295a0616a897441acec",
  "0x001866ae5b3de6caa5a51543fd9fb64f524f5478",
  "0x8b99f3660622e21f2910ecca7fbe51d654a1517d",
  "0xab83d182f3485cf1d6ccdd34c7cfef95b4c08da4",
  "0xc365c3315cf926351ccaf13fa7d19c8c4058c8e1",
  "0x61189da79177950a7272c88c6058b96d4bcd6be2",
  "0x4fabb145d64652a948d72533023f6e7a623c7c53",
  "0xc9a2c4868f0f96faaa739b59934dc9cb304112ec",
  "0x47ac0fb4f2d84898e4d9e7b4dab3c24507a6d503",
  "0xb8c77482e45f1f44de1745f52c74426c631bdd52",
  "0x0b95993a39a363d99280ac950f5e4536ab5c5566",
  "0x1074253202528777561f83817d413e91bfa671d4",
  "0x170c7c38419767816cc7ec519da67d1a4dc43826",
  "0x9430801ebaf509ad49202aabc5f5bc6fd8a3daf8",
  "0xe7804c37c13166ff0b37f5ae0bb07a3aebb6e245", // Polygon Binance
  "0x1151314c646ce4e0efd76d1af4760ae66a9fe30f", // Bitfinex
  "0x36a85757645e8e8aec062a1dee289c7d615901ca",
  "0xc56fefd1028b0534bfadcdb580d3519b5586246e",
  "0x0b73f67a49273fc4b9a65dbd25d7d0918e734e63",
  "0x482f02e8bc15b5eabc52c6497b425b3ca3c821e8",
  "0xe92d1a43df510f82c66382592a047d288f85226f",
  "0x742d35cc6634c0532925a3b844bc454e4438f44e",
  "0x8103683202aa8da10536036edef04cdd865c225e",
  "0x876eabf441b2ee5b5b0554fd502a8e0600950cfa",
  "0xdcd0272462140d0a3ced6c4bf970c7641f08cd2c",
  "0x4fdd5eb2fb260149a3903859043e962ab89d8ed4",
  "0x1b29dd8ff0eb3240238bf97cafd6edea05d5ba82",
  "0x30a2ebf10f34c6c4874b0bdd5740690fd2f3b70c",
  "0x3f7e77b627676763997344a1ad71acb765fc8ac5",
  "0x59448fe20378357f206880c58068f095ae63d5a5",
  "0x7727e5113d1d161373623e5f49fd568b4f543a9e",
  "0x0e55c54249f25f70d519b7fb1c20e3331e7ba76d",
  "0x5dbdebcae07cc958ba5290ff9deaae554e29e7b4",
  "0x2ee3b2df6534abc759ffe994f7b8dcdfaa02cd31",
  "0xe1f3c653248de6894d683cb2f10de7ca2253046f",
  "0x2903cadbe271e057edef157340b52a5898d7424f",
  "0x36928500bc1dcd7af6a2b4008875cc336b927d57",
  "0x14d06788090769f669427b6aea1c0240d2321f34",
  "0x77134cbc06cb00b66f4c7e623d5fdbf6777635ec",
  "0x2af5d2ad76741191d15dfe7bf6ac92d4bd912ca3",
  "0x0639556F03714A74a5fEEaF5736a4A64fF70D206", // Bitget
  "0x88d34944cf554e9cccf4a24292d891f620e9c94f", // Bithumb
  "0x186549a4ae594fc1f70ba4cffdac714b405be3f9",
  "0xd273bd546b11bd60214a2f9d71f22a088aafe31b",
  "0x558553d54183a8542f7832742e7b4ba9c33aa1e6",
  "0x3052cd6bf951449a984fe4b5a38b46aef9455c8e",
  "0x2140efd7ba31169c69dfff6cdc66c542f0211825",
  "0xa0ff1e0f30b5dda2dc01e7e828290bc72b71e57d",
  "0xc1da8f69e4881efe341600620268934ef01a3e63",
  "0xb4460b75254ce0563bb68ec219208344c7ea838c",
  "0x15878e87c685f866edfaf454be6dc06fa517b35b",
  "0x31d03f07178bcd74f9099afebd23b0ae30184ab5",
  "0xed48dc0628789c2956b1e41726d062a86ec45bff",
  "0x3fbe1f8fc5ddb27d428aa60f661eaaab0d2000ce",
  "0x03599a2429871e6be1b154fb9c24691f9d301865",
  "0xbb5a0408fa54287b9074a2f47ab54c855e95ef82",
  "0x5521a68d4f8253fc44bfb1490249369b3e299a4a",
  "0x8fa8af91c675452200e49b4683a33ca2e1a34e42",
  "0x3b83cd1a8e516b6eb9f1af992e9354b15a6f9672",
  "0xe79eef9b9388a4ff70ed7ec5bccd5b928ebb8bd1", // BitMart
  "0x68b22215ff74e3606bd5e6c1de8c2d68180c85f7",
  "0x3ab28ecedea6cdb6feed398e93ae8c7b316b1182",
  "0xeea81c4416d71cef071224611359f6f99a4c4294", // BitMEX
  "0xfb8131c260749c7835a08ccbdb64728de432858e",
  "0xfbb1b73c4f0bda4f67dca266ce6ef42f520fbb98", // Bittrex
  "0xe94b04a0fed112f3664e45adb2b8915693dd5ff3",
  "0x66f820a414680b5bcda5eeca5dea238543f42054",
  "0xa3c1e324ca1ce40db73ed6026c4a177f099b5770",
  "0xf89d7b9c864f589bbf53a82105107622b35eaa40", // Bybit
  "0x71660c4005ba85c37ccec55d0c4493e66fe775d3", // Coinbase
  "0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43",
  "0x77696bb39917c91a0c3908d577d5e322095425ca",
  "0x7c195d981abfdc3ddecd2ca0fed0958430488e34",
  "0x95a9bd206ae52c4ba8eecfc93d18eacdd41c88cc",
  "0xb739d0895772dbb71a89a3754a160269068f0d45",
  "0x503828976d22510aad0201ac7ec88293211d23da",
  "0xddfabcdc4d8ffc6d5beaf154f18b778f892a0740",
  "0x3cd751e6b0078be393132286c442345e5dc49699",
  "0xb5d85cbf7cb3ee0d56b3bb207d5fc4b82f43f511",
  "0xeb2629a2734e272bcc07bda959863f316f4bd4cf",
  "0xd688aea8f7d450909ade10c47faa95707b0682d9",
  "0x02466e547bfdab679fc49e96bbfc62b9747d997c",
  "0x6b76f8b1e9e59913bfe758821887311ba1805cab",
  "0xbe3c68821d585cf1552214897a1c091014b1eb0a",
  "0xf6874c88757721a02f47592140905c4336dfbc61",
  "0x881d4032abe4188e2237efcd27ab435e81fc6bb1",
  "0x6c8dd0e9cc58c07429e065178d88444b60e60b80",
  "0xbc8ec259e3026ae0d87bc442d034d6882ce4a35c",
  "0x02d24cab4f2c3bf6e6eb07ea07e45f96baccffe7",
  "0xce352e98934499be70f641353f16a47d9e1e3abd",
  "0x90e18a6920985dbacc3d76cf27a3f2131923c720",
  "0x4b23d52eff7c67f5992c2ab6d3f69b13a6a33561",
  "0xd2276af80582cac230edc4c42e9a9c096f3c09aa",
  "0xa090e606e30bd747d4e6245a1517ebe430f0057e",
  "0x904cc2b2694ffa78f04708d6f7de205108213126", // Deribit
  "0x63f41034871535cee49996cc47719891fe03dff9",
  "0xa0f6121319a34f24653fb82addc8dd268af5b9e1",
  "0x062448f804191128d71fc72e10a1d13bd7308e7e",
  "0xa7e15ef7c01b58ebe5ef74aa73625ae4b11fe754",
  "0x6b378be3c9642ccf25b1a27facb8ace24ac34a12",
  "0x2eed6a08fb89a5cd111efa33f8dca46cfbeb370f",
  "0xcfee6efec3471874022e205f4894733c42cbbf64",
  "0x5f397b62502e255f68382791947d54c4b2d37f09",
  "0x77021d475e36b3ab1921a0e3a8380f069d3263de",
  "0x0d0707963952f2fba59dd06f2b425ace40b492fe", // Gate.io
  "0x7793cd85c11a924478d358d49b05b37e91b5810f",
  "0x1c4b70a3968436b9a0a9cf5205c787eb81bb558c",
  "0x234ee9e35f8e9749a002fc42970d570db716453b",
  "0xc882b111a75c0c657fc507c04fbfcd2cc984f071",
  "0xd793281182a0e3e023116004778f45c29fc14f19",
  "0x6596da8b65995d5feacff8c2936f0b7a2051b0d0",
  "0xd24400ae8bfebb18ca49be86258a3c749cf46853", // Gemini
  "0x6fc82a5fe25a5cdb58bc74600a40a69c065263f8",
  "0x61edcdf5bb737adffe5043706e7c5bb1f1a56eea",
  "0x5f65f7b609678448494de4c87521cdf6cef1e932",
  "0xb302bfe9c246c6e150af70b1caaa5e3df60dac05",
  "0x8d6f396d210d385033b348bcae9e4f9ea4e045bd",
  "0xd69b0089d9ca950640f5dc9931a41a5965f00303",
  "0xa81011ae274ef6debd3bdab634102c7b6c2c452d", // HitBTC (Payout)
  "0x274f3c32c90517975e29dfc209a23f315c1e5fc7", // Hotbit
  "0x8533a0bd9310eb63e7cc8e1116c18a3d67b1976a",
  "0x562680a4dc50ed2f14d75bf31f494cfe0b8d10a1",
  "0xab5c66752a9e8167967685f1450532fb96d5d24f", // Huobi
  "0xe93381fb4c4f14bda253907b18fad305d799241a",
  "0xfa4b5be3f2f84f56703c42eb22142744e95a2c58",
  "0x46705dfff24256421a05d056c29e81bdc09723b8",
  "0x32598293906b5b17c27d657db3ad2c9b3f3e4265",
  "0x5861b8446a2f6e19a067874c133f04c578928727",
  "0x926fc576b7facf6ae2d08ee2d4734c134a743988",
  "0xeec606a66edb6f497662ea31b5eb1610da87ab5f",
  "0x7ef35bb398e0416b81b019fea395219b65c52164",
  "0x229b5c097f9b35009ca1321ad2034d4b3d5070f6",
  "0xd8a83b72377476d0a66683cde20a8aad0b628713",
  "0x6748f50f686bfbca6fe8ad62b22228b87f31ff2b",
  "0x90e9ddd9d8d5ae4e3763d0cf856c97594dea7325",
  "0x30741289523c2e4d2a62c7d6722686d14e723851",
  "0x6f48a3e70f0251d1e83a989e62aaa2281a6d5380",
  "0xf056f435ba0cc4fcd2f1b17e3766549ffc404b94",
  "0x137ad9c4777e1d36e4b605e745e8f37b2b62e9c5",
  "0x5401dbf7da53e1c9dbf484e3d69505815f2f5e6e",
  "0x034f854b44d28e26386c1bc37ff9b20c6380b00d",
  "0x0577a79cfc63bbc0df38833ff4c4a3bf2095b404",
  "0x0c6c34cdd915845376fb5407e0895196c9dd4eec",
  "0x794d28ac31bcb136294761a556b68d2634094153",
  "0xfdb16996831753d5331ff813c29a93c76834a0ad",
  "0x34189c75cbb13bdb4f5953cda6c3045cfca84a9e",
  "0xb4cd0386d2db86f30c1a11c2b8c4f4185c1dade9",
  "0x4d77a1144dc74f26838b69391a6d3b1e403d0990",
  "0x28ffe35688ffffd0659aee2e34778b0ae4e193ad",
  "0xcac725bef4f114f728cbcfd744a731c2a463c3fc",
  "0x73f8fc2e74302eb2efda125a326655acf0dc2d1b",
  "0x0a98fb70939162725ae66e626fe4b52cff62c2e5",
  "0xf66852bc122fd40bfecc63cd48217e88bda12109",
  "0x49517ca7b7a50f592886d4c74175f4c07d460a70",
  "0x58c2cb4a6bee98c309215d0d2a38d7f8aa71211c",
  "0xeee28d484628d41a82d01e21d12e2e78d69920da",
  "0x39d9f4640b98189540a9c0edcfa95c5e657706aa",
  "0x5c985e89dde482efe97ea9f1950ad149eb73829b",
  "0xdc76cd25977e0a5ae17155770273ad58648900d3",
  "0xadb2b42f6bd96f5c65920b9ac88619dce4166f94",
  "0xa8660c8ffd6d578f657b72c0c811284aef0b735e",
  "0x1062a747393198f70f71ec65a582423dba7e5ab3",
  "0x9d6d492bd500da5b33cf95a5d610a73360fcaaa0",
  "0xa66daa57432024023db65477ba87d4e7f5f95213",
  "0x6f259637dcd74c767781e37bc6133cd6a68aa161",
  "0xe0d513cf39b52a09aefcef25e91dda3a2636329a",
  "0xfd54078badd5653571726c3370afb127351a6f26",
  "0x18916e1a2933cb349145a280473a5de8eb6630cb",
  "0xdb0e89a9b003a28a4055ef772e345e8089987bfd",
  "0xf0458aaaf6d49192d3b4711960635d5fa2114e71",
  "0x07ef60deca209ea0f3f3f08c1ad21a6db5ef9d33",
  "0x2910543af39aba0cd09dbb2d50200b3e800a63d2", // Kraken
  "0xae2d4617c862309a3d75a0ffb358c7a5009c673f",
  "0x43984d578803891dfa9706bdeee6078d80cfc79e",
  "0x66c57bf505a85a74609d2c83e94aabb26d691e1f",
  "0xda9dfa130df4de4673b89022ee50ff26f6ea73cf",
  "0xa83b11093c858c86321fbc4c20fe82cdbd58e09e",
  "0x0a869d79a7052c7f1b55a8ebabbea3420f0d1e13",
  "0xe853c56864a2ebe4576a807d26fdc4a0ada51919",
  "0x267be1c1d684f78cb4f6a176c4911b741e4ffdc0",
  "0xfa52274dd61e1643d2205169732f29114bc240b3",
  "0x53d284357ec70ce289d6d64134dfac8e511c8a3d",
  "0x89e51fa8ca5d66cd220baed62ed01e8951aa7c40",
  "0xc6bed363b30df7f35b601a5547fe56cd31ec63da",
  "0x29728d0efd284d85187362faa2d4d76c2cfc2612",
  "0x2e7542ec36df6429d8c397f88c4cf0c925948f44",
  "0xa24787320ede4cc19d800bf87b41ab9539c4da9d",
  "0xe9f7ecae3a53d2a67105292894676b00d1fab785",
  "0x2b5634c42055806a59e9107ed44d43c426e58258", // Kucoin
  "0xcad621da75a66c7a8f4ff86d30a2bf981bfc8fdd",
  "0xec30d02f10353f8efc9601371f56e808751f396f",
  "0x738cf6903e6c4e699d1c2dd9ab8b67fcdb3121ea",
  "0xd89350284c7732163765b23338f2ff27449e0bf5",
  "0x88bd4d3e2997371bceefe8d9386c6b5b4de60346",
  "0xb8e6d31e7b212b2b7250ee9c26c56cebbfbe6b23",
  "0x689c56aef474df92d44a1b70850f808488f9769c",
  "0xa1d8d972560c2f8144af871db508f0b0b10a3fbf",
  "0x4ad64983349c49defe8d7a4686202d24b25d0ce8",
  "0x1692e170361cefd1eb7240ec13d048fd9af6d667",
  "0xd6216fc19db775df9774a6e33526131da7d19a2c",
  "0xe59cd29be3be4461d79c0881d238cbe87d64595a",
  "0x899b5d52671830f567bf43a14684eb14e1f945fe",
  "0xf16e9b0d03470827a95cdfd0cb8a8a3b46969b91",
  "0x75e89d5979e4f6fba9f97c104c2f0afb3f1dcb88", // MEXC
  "0x6cc5f688a315f3dc28a7781717a9a798a59fda7b", // OKX
  "0xc5451b523d5fffe1351337a221688a62806ad91a",
  "0x42436286a9c8d63aafc2eebbca193064d68068f2",
  "0x69a722f0b5da3af02b4a205d6f0c285f4ed8f396",
  "0xc708a1c712ba26dc618f972ad7a187f76c8596fd",
  "0x6fb624b48d9299674022a23d92515e76ba880113",
  "0xf59869753f41db720127ceb8dbb8afaf89030de4",
  "0x65a0947ba5175359bb457d3b34491edf4cbf7997",
  "0x4d19c0a5357bc48be0017095d3c871d9afc3f21d",
  "0x5c52cc7c96bde8594e5b77d5b76d042cb5fae5f2",
  "0xe9172daf64b05b26eb18f07ac8d6d723acb48f99",
  "0x236f9f97e0e62388479bf9e5ba4889e46b0273c3",
  "0x7eb6c83ab7d8d9b8618c0ed973cbef71d1921ef2",
  "0xa7efae728d2936e78bda97dc267687568dd593f3",
  "0x2c8fbb630289363ac80705a1a61273f76fd5a161",
  "0x59fae149a8f8ec74d5bc038f8b76d25b136b9573",
  "0x98ec059dc3adfbdd63429454aeb0c990fba4a128",
  "0x5041ed759dd4afc3a72b8192c143f72f4724081a",
  "0xcba38020cd7b6f51df6afaf507685add148f6ab6",
  "0x461249076b88189f8ac9418de28b365859e46bfd",
  "0x32be343b94f860124dc4fee278fdcbd38c102d88", // Poloniex
  "0x209c4784ab1e8183cf58ca33cb740efbf3fc18ef",
  "0xb794f5ea0ba39494ce839613fffba74279579268",
  "0xa910f92acdaf488fa6ef02174fb86208ad7722ba",
];

const gnosisExecutionSuccessEventABI = "event ExecutionSuccess(bytes32 txHash, uint256 payment)";
const multiSendSig = "0x8d80ff0a";
const permitSig = "0xd505accf";
const uniswapPermitSig = "0x2a2d80d1";

const upgradedEventABI = ["event Upgraded(address indexed implementation)"];

const permitFunctionABI =
  "function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) external";

const daiPermitFunctionABI =
  "function permit(address owner, address spender, uint256 nonce, uint256 deadline, bool allowed, uint8 v, bytes32 r, bytes32 s) external";

const uniswapPermitFunctionABI =
  "function permit(address owner, ((address token, uint160 value, uint48 expiration, uint48 nonce)[] details, address spender, uint256 deadline) permitBatch, bytes signature)";

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
  STABLECOINS,
  safeBatchTransferFrom1155Sig,
  transferFromSig,
  CEX_ADDRESSES,
  UNISWAP_PERMIT_2,
  gnosisExecutionSuccessEventABI,
  multiSendSig,
  permitSig,
  uniswapPermitSig,
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

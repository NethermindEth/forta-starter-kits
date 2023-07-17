const { ethers } = require("forta-agent");
const { ScanCountType } = require("bot-alert-rate");
const { IGNORED_ADDRESSES, BOT_ID } = require("./utils");
const {
  getAddressType,
  getContractCreator,
  createPermitAlert,
  createPermitScamAlert,
  createPermitSuspiciousContractAlert,
  createPermitScamCreatorAlert,
  createPermitInfoAlert,
} = require("./helper");
const AddressType = require("./address-type");
const permitsHandleTransaction = async (
  txEvent,
  permitFunctions,
  counters,
  chainId,
  scamAddresses,
  cachedAddresses,
  provider,
  objects,
  scamSnifferDB,
  suspiciousContracts,
  findings,
  calculateAlertRate
) => {
  const txFrom = ethers.utils.getAddress(txEvent.from);
  hash = txEvent.hash;
  for (const func of permitFunctions) {
    counters.totalPermits += 1;

    let { address: asset } = func;
    let { owner, spender, deadline, value } = func.args;
    if (deadline) {
      deadline = Number(deadline.toString());
    }

    if (func.args.permitSingle) {
      spender = func.args.permitSingle.spender;
      deadline = Number(func.args.permitSingle.deadline.toString());
      value = func.args.permitSingle.details.value.toString();
      asset = func.args.permitSingle.details.token.toLowerCase();
    }

    if (txFrom === owner || IGNORED_ADDRESSES.includes(spender)) {
      continue;
    }

    const msgSenderType = await getAddressType(
      txFrom,
      scamAddresses,
      cachedAddresses,
      provider,
      txEvent.blockNumber,
      chainId,
      false
    );

    const spenderType = await getAddressType(
      spender,
      scamAddresses,
      cachedAddresses,
      provider,
      txEvent.blockNumber,
      chainId,
      false
    );

    if (
      (spenderType === AddressType.LowNumTxsUnverifiedContract ||
        spenderType === AddressType.EoaWithLowNonce ||
        spenderType === AddressType.ScamAddress) &&
      (msgSenderType === AddressType.LowNumTxsUnverifiedContract ||
        msgSenderType === AddressType.EoaWithLowNonce ||
        msgSenderType === AddressType.ScamAddress)
    ) {
      if (!objects.permissions[spender]) objects.permissions[spender] = [];

      objects.permissions[spender].push({
        asset,
        owner,
        hash,
        deadline,
        value: value ? value : 0,
      });
      if (spenderType !== AddressType.ScamAddress && msgSenderType !== AddressType.ScamAddress) {
        const anomalyScore = await calculateAlertRate(
          chainId,
          BOT_ID,
          "ICE-PHISHING-ERC20-PERMIT",
          ScanCountType.CustomScanCount,
          counters.totalPermits
        );
        findings.push(createPermitAlert(txFrom, spender, owner, asset, anomalyScore, hash));
      } else {
        const scamDomains = Object.keys(scamSnifferDB.data).filter(
          (key) =>
            scamSnifferDB.data[key].includes(txFrom.toLowerCase()) ||
            scamSnifferDB.data[key].includes(spender.toLowerCase())
        );
        let _scamAddresses = [];
        if (spenderType === AddressType.ScamAddress) {
          _scamAddresses.push(spender);
        }
        if (msgSenderType === AddressType.ScamAddress) {
          _scamAddresses.push(txFrom);
        }
        const anomalyScore = await calculateAlertRate(
          chainId,
          BOT_ID,
          "ICE-PHISHING-ERC20-SCAM-PERMIT",
          ScanCountType.CustomScanCount,
          counters.totalPermits
        );
        findings.push(
          createPermitScamAlert(txFrom, spender, owner, asset, _scamAddresses, scamDomains, anomalyScore, hash)
        );
      }
    } else if (spenderType === AddressType.LowNumTxsVerifiedContract || spenderType === AddressType.EoaWithHighNonce) {
      const suspiciousContractFound = Array.from(suspiciousContracts).find(
        (contract) => contract.address === spender || contract.creator === spender
      );

      if (suspiciousContractFound) {
        const anomalyScore = await calculateAlertRate(
          chainId,
          BOT_ID,
          "ICE-PHISHING-ERC20-SUSPICIOUS-PERMIT",
          ScanCountType.CustomScanCount,
          counters.totalPermits
        );
        findings.push(
          createPermitSuspiciousContractAlert(
            txFrom,
            spender,
            owner,
            asset,
            suspiciousContractFound,
            anomalyScore,
            hash
          )
        );
      }

      if (spenderType === AddressType.LowNumTxsVerifiedContract) {
        let spenderContractCreator, spenderContractCreatorType;

        spenderContractCreator = await getContractCreator(spender, chainId);
        if (spenderContractCreator) {
          spenderContractCreatorType = await getAddressType(
            spenderContractCreator,
            scamAddresses,
            cachedAddresses,
            provider,
            txEvent.blockNumber,
            chainId,
            false
          );
        }

        if (spenderContractCreator && spenderContractCreatorType === AddressType.ScamAddress) {
          const scamDomains = Object.keys(scamSnifferDB.data).filter((key) =>
            scamSnifferDB.data[key].includes(spenderContractCreator.toLowerCase())
          );
          if (scamDomains.length > 0) {
            const anomalyScore = await calculateAlertRate(
              chainId,
              BOT_ID,
              "ICE-PHISHING-ERC20-SCAM-CREATOR-PERMIT",
              ScanCountType.CustomScanCount,
              counters.totalPermits
            );
            findings.push(
              createPermitScamCreatorAlert(
                txFrom,
                spender,
                owner,
                asset,
                spenderContractCreator,
                scamDomains,
                anomalyScore,
                hash
              )
            );
          }
        }
      }

      if (!objects.permissionsInfoSeverity[spender]) objects.permissionsInfoSeverity[spender] = [];
      objects.permissionsInfoSeverity[spender].push({
        asset,
        owner,
        hash,
        deadline,
        value: value ? value : 0,
      });
      const anomalyScore = await calculateAlertRate(
        chainId,
        BOT_ID,
        "ICE-PHISHING-ERC20-PERMIT-INFO",
        ScanCountType.CustomScanCount,
        counters.totalPermits
      );
      findings.push(createPermitInfoAlert(txFrom, spender, owner, asset, anomalyScore, hash));
    }
  }
};

module.exports = {
  permitsHandleTransaction,
};

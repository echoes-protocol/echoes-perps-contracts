import hre, { ethers, upgrades } from "hardhat";

async function deployContract() {
  const factory = await ethers.getContractFactory("RFL");
  const contract = await upgrades.deployProxy(factory, [
    "0xf42bF799DD9E70605083e38e5a3bd6AAe63A8516", // admin
    "0xB0FB2aE3BaF577061CA28C1Ba47Dd1Db2f00F8c5", // minter
    "0x29219dd400f2Bf60E5a23d13Be72B486D4038894", // collateral
    "1788048000" // referralOpenTimestamp
  ]);
  await contract.deployed();
  try {
    await hre.run("verify:verify", {
      address: contract.address
    });
  } catch {
    console.log("Failed to verify");
  }
  console.log("Contract deployed at:", contract.address);
}

deployContract()
  .then(() => {
    console.log("done");
  })
  .catch(console.log);

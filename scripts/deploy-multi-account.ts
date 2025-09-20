import hre, { ethers, upgrades } from "hardhat";

async function deployContract() {
  const factory = await ethers.getContractFactory("MultiAccount");
  const contract = await upgrades.deployProxy(factory, [
    "0xf42bF799DD9E70605083e38e5a3bd6AAe63A8516", // admin
    "0x", // accountImplementation
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

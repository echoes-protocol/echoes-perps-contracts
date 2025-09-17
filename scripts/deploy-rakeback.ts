import hre, { ethers, upgrades } from "hardhat";

async function deployContract() {
  const factory = await ethers.getContractFactory("Rakeback");
  const contract = await upgrades.deployProxy(factory, [
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

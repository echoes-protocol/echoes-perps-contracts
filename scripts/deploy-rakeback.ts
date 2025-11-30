import hre, { ethers, upgrades } from "hardhat";

async function deployContract() {
  const factory = await ethers.getContractFactory("Rakeback");
  const contract = await upgrades.deployProxy(factory, [
    "0xf42bF799DD9E70605083e38e5a3bd6AAe63A8516", // admin
    "0x803de354cbd853D9aE3BC58131A5D538DE7a72E3", // symmio
    "0xB0FB2aE3BaF577061CA28C1Ba47Dd1Db2f00F8c5", // multiAccount
    "0x641B68DafE233b780516F31D14024d8eBE8C1C8c", // rfl
    "0x0000000000000000000000000000000000000000", // fee collector -- deprecated, kept for storage integrity
    "0xf42bF799DD9E70605083e38e5a3bd6AAe63A8516", // vibe signer
    "0xf42bF799DD9E70605083e38e5a3bd6AAe63A8516", // vibe fee receiver
    "300", // signature valid time
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

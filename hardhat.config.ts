import "dotenv/config";
import "@nomicfoundation/hardhat-toolbox";
import "hardhat-deploy";
import "@nomiclabs/hardhat-ethers";
import "@openzeppelin/hardhat-upgrades";
import { HttpNetworkUserConfig } from "hardhat/types";
import {
  HardhatUserConfig,
  HttpNetworkAccountsUserConfig,
} from "hardhat/types";

const PRIVATE_KEY = process.env.PRIVATE_KEY;

const accounts: HttpNetworkAccountsUserConfig | undefined = PRIVATE_KEY
  ? [PRIVATE_KEY]
  : undefined;

if (accounts == null) {
  console.warn(
    "Could not find MNEMONIC or PRIVATE_KEY environment variables. It will not be possible to execute transactions in your example."
  );
}

const networks: { [networkName: string]: HttpNetworkUserConfig } = {
  sepolia: {
    url: "https://rpc.ankr.com/eth_sepolia",
    chainId: 11155111,
    accounts,
    gas: 1600000,
    gasPrice: 5616147756,
  },
  bsc: {
    url: "https://bsc-rpc.publicnode.com",
    chainId: 56,
    accounts
  },
  bscTestnet: {
    url: "https://bsc-testnet-rpc.publicnode.com",
    chainId: 97,
    accounts,
  },
  arbitrumOne: {
    url: "https://arb1.arbitrum.io/rpc",
    chainId: 42161,
    accounts
  },
  arbitrumSepolia: {
    url: "https://arbitrum-sepolia-rpc.publicnode.com",
    chainId: 421614,
    accounts,
  },
  polygon: {
    url: `https://polygon.llamarpc.com`,
    chainId: 137,
    accounts,
    gas: 2500000,
    gasPrice: 100000000000,
  },
  avalanche: {
    url: `https://rpc.ankr.com/avalanche`,
    chainId: 43114,
    accounts,
  },
  ftm: {
    url: `https://rpcapi.fantom.network`,
    chainId: 250,
    accounts,
  },
  fuji: {
    url: `https://avalanche-fuji-c-chain-rpc.publicnode.com`,
    chainId: 43113,
    accounts,
  },
  base: {
    url: "https://mainnet.base.org",
    chainId: 8453,
    accounts,
  },
  sonic: {
    url: "https://rpc.soniclabs.com",
    chainId: 146,
    accounts,
  },
};

const config: HardhatUserConfig = {
  defaultNetwork: "hardhat",
  networks: {
    hardhat: {},
    ...networks,
  },
  solidity: {
    compilers: [
      {
        version: "0.8.20",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
          viaIR: true,
          // outputSelection: {
          //   "*": {
          //     "*": [
          //       // "abi",
          //       // "evm.bytecode",
          //       // "evm.deployedBytecode",
          //       "metadata", // <-- add this
          //     ]
          //   },
          // },
        },
      },
    ],
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts",
  },
  mocha: {
    timeout: 40000,
  },
  etherscan: {
    apiKey: {
      mainnet: process.env.ETHERSCAN_KEY || "",
      sepolia: process.env.ETHERSCAN_KEY || "",
      goerli: process.env.ETHERSCAN_KEY || "",
      bscTestnet: process.env.BSCSCAN_KEY || "",
      bsc: process.env.BSCSCAN_KEY || "",
      polygon: process.env.POLYGON_KEY || "",
      polygonMumbai: process.env.POLYGON_KEY || "",
      lineaMainnet: process.env.LINEASCAN_KEY || "",
      optimisticEthereum: process.env.OPTIMISM_KEY || "",
      avalancheFujiTestnet: process.env.AVALANCHE_KEY || "",
      arbitrumOne: process.env.ARBSCAN_KEY || "",
      arbitrumSepolia: process.env.ARBSCAN_KEY || "",
      avalanche: process.env.AVALANCHE_KEY || "",
      ftm: process.env.FTMSCAN_KEY || "",
      base: process.env.BASE_SCAN || "",
      sonic: process.env.SONIC_SCAN || "",
    },
    customChains: [
      {
        network: "ftm",
        chainId: 250,
        urls: {
          apiURL: "https://api.ftmscan.com/api",
          browserURL: "https://ftmscan.com/",
        },
      },
      {
        network: "lineaMainnet",
        chainId: 59144,
        urls: {
          apiURL: "https://api.lineascan.build/api",
          browserURL: "https://lineascan.build/",
        },
      },
      {
        network: "arbitrumSepolia",
        chainId: 421614,
        urls: {
          apiURL: "https://api-sepolia.arbiscan.io/api",
          browserURL: "https://sepolia.arbiscan.io/",
        },
      },
      {
        network: "base",
        chainId: 8453,
        urls: {
          apiURL: `https://api.basescan.org/api`,
          browserURL: "https://basescan.org/",
        },
      },
      {
        network: "sonic",
        chainId: 146,
        urls: {
          apiURL: "https://api.sonicscan.org/api",
          browserURL: "https://sonicscan.org"
        }
      },
    ],
  },
  namedAccounts: {
    deployer: {
      default: 0, // wallet address of index[0], of the mnemonic in .env
    },
  },
};

export default config;

import { readFileSync, writeFileSync } from 'node:fs';
import { JsonRpcProvider, Wallet, ContractFactory } from 'ethers';
try { process.loadEnvFile('.env'); } catch {}
const artifact = JSON.parse(readFileSync('artifacts/FileRegistry.json'));
const provider = new JsonRpcProvider(process.env.RPC_URL || 'http://127.0.0.1:8545');
if ((await provider.getNetwork()).chainId !== 31337n) throw new Error('Local demo deployment requires chain ID 31337');
const signer = new Wallet(process.env.PROXY_PK, provider);
const contract = await new ContractFactory(artifact.abi, artifact.evm.bytecode.object, signer).deploy(signer.address);
await contract.waitForDeployment();
writeFileSync('deployment.json', JSON.stringify({ address: await contract.getAddress(), abi: artifact.abi, chainId: 31337 }, null, 2));
console.log(`Deployed FileRegistry at ${await contract.getAddress()}`);

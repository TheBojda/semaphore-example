import { Identity } from "@semaphore-protocol/identity"
import { Group } from "@semaphore-protocol/group"
import { generateProof } from "@semaphore-protocol/proof"
import { verifyProof } from "@semaphore-protocol/proof"
import { assert, expect } from "chai";
import { run, ethers } from "hardhat"
import download from "download"
import fs from "fs"
import { Semaphore } from "../build/typechain"
import { config } from "../package.json"

describe("Semaphore tests", () => {

    const wasmFilePath = `${config.paths.build["snark-artifacts"]}/semaphore.wasm`
    const zkeyFilePath = `${config.paths.build["snark-artifacts"]}/semaphore.zkey`

    let ADMIN: any

    before(async () => {
        const snarkArtifactsPath = config.paths.build["snark-artifacts"]
        const url = `http://www.trusted-setup-pse.org/semaphore/${20}`

        if (!fs.existsSync(snarkArtifactsPath)) {
            fs.mkdirSync(snarkArtifactsPath, { recursive: true })
        }

        if (!fs.existsSync(`${snarkArtifactsPath}/semaphore.zkey`)) {
            await download(`${url}/semaphore.wasm`, snarkArtifactsPath)
            await download(`${url}/semaphore.zkey`, snarkArtifactsPath)
        }

        const signers = await ethers.getSigners()
        ADMIN = signers[0]
    })

    it("Testing off-chain signaling", async () => {
        const groupId = 1
        const merkleTreeDepth = 20
        const externalNullifier = 1212
        const signal = 1

        let identity = new Identity()

        const group = new Group(groupId, merkleTreeDepth)

        group.addMember(identity.commitment)

        const fullProof = await generateProof(identity, group, externalNullifier, signal, {
            zkeyFilePath: zkeyFilePath,
            wasmFilePath: wasmFilePath
        })

        assert(await verifyProof(fullProof, merkleTreeDepth))
    })

    it("Testing on-chain signaling", async () => {
        const { semaphore }: { semaphore: Semaphore } = await run("deploy:semaphore", { logs: false })

        const groupId = 1
        const merkleTreeDepth = 20
        const externalNullifier = 1212
        const signal = 1

        let identity = new Identity()

        await semaphore["createGroup(uint256,uint256,address)"](groupId, merkleTreeDepth, ADMIN.address)

        await semaphore.addMember(groupId, identity.commitment)

        // generate proof from events

        const group = new Group(groupId, merkleTreeDepth)

        const events = await semaphore.queryFilter(semaphore.filters["MemberAdded(uint256,uint256,uint256,uint256)"](groupId))
        for (let event of events) {
            group.addMember(event.args.identityCommitment.toBigInt())
        }

        assert.equal((await semaphore.getMerkleTreeRoot(groupId)).toBigInt(), group.root)

        const fullProof = await generateProof(identity, group, externalNullifier, signal, {
            zkeyFilePath: zkeyFilePath,
            wasmFilePath: wasmFilePath
        })

        // ---

        const transaction = await semaphore.verifyProof(
            groupId,
            fullProof.merkleTreeRoot,
            fullProof.signal,
            fullProof.nullifierHash,
            fullProof.externalNullifier,
            fullProof.proof
        )

        await expect(transaction)
            .to.emit(semaphore, "ProofVerified")
            .withArgs(groupId, fullProof.merkleTreeRoot, fullProof.nullifierHash, fullProof.externalNullifier, fullProof.signal)
    })

})
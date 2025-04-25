import { ProofGenerator } from "@maci-protocol/contracts";
import { MaciState, Poll, type IJsonMaciState, type IJsonPoll } from "@maci-protocol/core";
import { Keypair, PrivateKey } from "@maci-protocol/domainobjs";

import fs from "fs";
import path from "path";

import type { IGenerateProofsArgs, IGenerateProofsData } from "./types";

import { getPollContracts } from "../poll/utils";
import { doesPathExist } from "../utils/files";

/**
 * Validates the existence of necessary proof generation artifacts.
 * @param args - Proof generation arguments.
 */
const validateProofArtifacts = (args: IGenerateProofsArgs): void => {
  const {
    useWasm,
    processWasm,
    tallyWasm,
    rapidsnark,
    processWitgen,
    tallyWitgen,
    processDatFile,
    tallyDatFile,
    processZkey,
    tallyZkey,
  } = args;

  const requiredZkeys = [processZkey, tallyZkey];
  const [zkExists, missingZk] = doesPathExist(requiredZkeys);
  if (!zkExists) {
    throw new Error(`Could not find required zkey file: ${missingZk}.`);
  }

  if (useWasm) {
    if (!processWasm) {
      throw new Error("Process wasm file location must be specified when useWasm is true.");
    }
    if (!tallyWasm) {
      throw new Error("Tally wasm file location must be specified when useWasm is true.");
    }

    const requiredWasm = [processWasm, tallyWasm];
    const [wasmExists, missingWasm] = doesPathExist(requiredWasm);
    if (!wasmExists) {
      throw new Error(`Could not find required wasm file: ${missingWasm}.`);
    }
  } else {
    if (!rapidsnark) {
      throw new Error("Rapidsnark file location must be specified when useWasm is false.");
    }
    if (!processWitgen) {
      throw new Error("Process witgen file location must be specified when useWasm is false.");
    }
    if (!tallyWitgen) {
      throw new Error("Tally witgen file location must be specified when useWasm is false.");
    }

    // Assuming dat files are required with rapidsnark/witgen
    const requiredWitgenArtifacts = [rapidsnark, processWitgen, tallyWitgen, processDatFile!, tallyDatFile!];
    const [witgenExists, missingWitgen] = doesPathExist(requiredWitgenArtifacts);
    if (!witgenExists) {
      throw new Error(`Could not find required witgen artifact: ${missingWitgen}.`);
    }
  }
};

// Define an interface for the structure of the poll state file
interface IPollStateFile {
  maciState: IJsonMaciState;
  poll: IJsonPoll;
}

/**
 * Generate proofs for the message processing and tally calculations
 * @param args - The arguments for the genProofs command
 * @returns The tally data
 */
export const generateProofs = async (args: IGenerateProofsArgs): Promise<IGenerateProofsData> => {
  const {
    outputDir,
    coordinatorPrivateKey,
    signer,
    maciAddress,
    pollId,
    ipfsMessageBackupFiles,
    stateFile,
    transactionHash,
    startBlock,
    endBlock,
    blocksPerBatch,
    rapidsnark,
    useQuadraticVoting,
    tallyZkey,
    tallyWitgen,
    tallyWasm,
    processZkey,
    processWitgen,
    processWasm,
    tallyFile,
    incremental,
  } = args;

  // Validate required file paths early
  validateProofArtifacts(args);

  const network = await signer.provider?.getNetwork();

  if (!maciAddress) {
    throw new Error("Please provide a MACI contract address");
  }

  if (!PrivateKey.isValidSerializedPrivKey(coordinatorPrivateKey)) {
    throw new Error("Invalid MACI private key");
  }

  // Ensure the output directory exists
  try {
    await fs.promises.mkdir(outputDir, { recursive: true });
  } catch (error: unknown) {
    // Check if the error is a NodeJS.ErrnoException and if the code is EEXIST
    if (typeof error === "object" && error !== null && "code" in error && error.code !== "EEXIST") {
      // Wrap the original error message or provide a new one
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Failed to create output directory: ${message}`); // Throw an actual Error object
    }
    // Ignore EEXIST error
  }

  const maciPrivateKey = PrivateKey.deserialize(coordinatorPrivateKey);
  const coordinatorKeypair = new Keypair(maciPrivateKey);

  const {
    poll: pollContract,
    maci: maciContract,
    tally: tallyContract,
  } = await getPollContracts({
    maciAddress,
    pollId,
    signer,
  });

  const [isStateAqMerged, tallyContractAddress] = await Promise.all([
    pollContract.stateMerged(),
    tallyContract.getAddress(),
  ]);

  if (!isStateAqMerged) {
    throw new Error("The state tree has not been merged yet. Please use the mergeSignups subcommand to do so.");
  }

  // --- State Loading / Preparation ---
  let maciState: MaciState;
  let foundPoll: Poll | undefined;
  const pollStateFilePath = path.join(outputDir, "poll.state.json");
  let stateLoaded = false;

  // Attempt to load state if not incremental and file exists
  if (!incremental) {
    try {
      await fs.promises.access(pollStateFilePath); // Check existence
      const fileContent = await fs.promises.readFile(pollStateFilePath, "utf8");
      // Parse first
      const parsedData: unknown = JSON.parse(fileContent);

      // Perform runtime validation to ensure it matches the expected structure
      if (
        typeof parsedData === "object" &&
        parsedData !== null &&
        "maciState" in parsedData &&
        "poll" in parsedData &&
        typeof parsedData.maciState === "object" && // Add more checks as needed
        typeof parsedData.poll === "object"
      ) {
        // Now it's safer to assert the type
        const stateData = parsedData as IPollStateFile;

        maciState = MaciState.fromJSON(stateData.maciState);
        foundPoll = maciState.polls.get(BigInt(pollId));

        if (foundPoll) {
          foundPoll.setCoordinatorKeypair(coordinatorPrivateKey);
          foundPoll.maciStateRef = maciState;
          stateLoaded = true;
        }
      } else {
        // Throw if structure is invalid, preventing unsafe assignment later
        throw new Error("Invalid poll state file structure after parsing.");
      }
    } catch (error) {
      // Log errors during loading for debugging, but allow fallback to regeneration
      // console.error(`INFO: Could not load state from ${pollStateFilePath}, preparing state from scratch. Error: ${error instanceof Error ? error.message : String(error)}`);
      // Ensure stateLoaded remains false
      stateLoaded = false;
    }
  }

  // Prepare state from scratch if not loaded successfully
  if (!stateLoaded) {
    maciState = await ProofGenerator.prepareState({
      maciContract,
      pollContract,
      maciPrivateKey,
      coordinatorKeypair,
      pollId,
      signer,
      outputDir,
      ipfsMessageBackupFiles,
      options: {
        stateFile,
        transactionHash,
        startBlock,
        endBlock,
        blocksPerBatch,
      },
    });
    // Re-fetch the poll from the newly prepared state
    foundPoll = maciState.polls.get(BigInt(pollId));
  }
  // --- End State Loading / Preparation ---

  if (!foundPoll) {
    // This error could happen if loading failed AND preparation failed
    throw new Error(`Poll ${pollId} not found after attempting load/prepare.`);
  }

  const proofGenerator = new ProofGenerator({
    poll: foundPoll,
    maciContractAddress: maciAddress,
    tallyContractAddress,
    rapidsnark,
    tally: {
      zkey: tallyZkey,
      witgen: tallyWitgen,
      wasm: tallyWasm,
    },
    mp: {
      zkey: processZkey,
      witgen: processWitgen,
      wasm: processWasm,
    },
    outputDir,
    tallyOutputFile: tallyFile,
    useQuadraticVoting,
  });

  const processProofs = await proofGenerator.generateMpProofs();
  const { proofs: tallyProofs, tallyData } = await proofGenerator.generateTallyProofs(
    network?.name ?? "",
    network?.chainId.toString() ?? "0",
  );

  // Save the final state
  const finalState = {
    maciState: maciState!.toJSON(), // Non-null assertion ok, state is guaranteed by logic above
    poll: foundPoll.toJSON(), // Non-null assertion ok, checked above
  };
  await fs.promises.writeFile(pollStateFilePath, JSON.stringify(finalState, null, 2));

  return { processProofs, tallyProofs, tallyData };
};

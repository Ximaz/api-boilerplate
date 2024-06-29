import type { Config } from "@jest/types";

const config: Config.InitialOptions = {
    verbose: true,
    transform: {},
    extensionsToTreatAsEsm: ['.ts'],
};

export default config;

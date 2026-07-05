const cp = require('child_process');
const fs = require('fs');

function getExportedSymbols(libPath) {
    const output = cp.execSync(`nm -gD ${libPath}`).toString();
    const symbols = [];
    for (const line of output.split('\n')) {
        if (line.includes(' T ') && line.includes('c_') && !line.includes('_cgo')) {
            symbols.push(line.split(' T ')[1].trim());
        }
    }
    return symbols.sort();
}

function main() {
    const oldLib = '../../electron/lib/libCwtchStegMS.so';
    const newLib = 'libCwtchStegMS_test.so';

    if (!fs.existsSync(oldLib)) {
        console.error(`Old lib not found: ${oldLib}`);
        process.exit(1);
    }
    
    if (!fs.existsSync(newLib)) {
        console.error(`New lib not found: ${newLib}`);
        process.exit(1);
    }

    const oldSymbols = getExportedSymbols(oldLib);
    const newSymbols = getExportedSymbols(newLib);

    let failed = false;
    for (const sym of oldSymbols) {
        if (!newSymbols.includes(sym)) {
            console.error(`Missing symbol in new lib: ${sym}`);
            failed = true;
        }
    }
    
    // We expect new lib to have c_SignChallenge
    if (!newSymbols.includes('c_SignChallenge')) {
        console.error(`Missing c_SignChallenge in new lib`);
        failed = true;
    }

    if (failed) {
        console.error("Differential symbol test FAILED");
        process.exit(1);
    } else {
        console.log("Differential symbol test PASSED");
    }
}

main();

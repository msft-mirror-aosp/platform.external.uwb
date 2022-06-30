// Copyright 2022, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::path::Path;
use std::process::Command;

fn main() {
    let out_dir = std::env::var_os("OUT_DIR").unwrap();
    let generated_file = "uci_packets.rs";

    if Path::new(generated_file).exists() {
        // Copy the rust code directly if the file exists.
        let dst_path = Path::new(&out_dir).join(generated_file);
        let result = std::fs::copy(generated_file, &dst_path);
        eprintln!("{} exists, copy to {:?}: {:?}", generated_file, dst_path, result);
        return;
    }

    // Generate the rust code by bluetooth_packetgen.
    // The binary should be compiled by `m bluetooth_packetgen -j32` before calling cargo.
    let output = Command::new("env")
        .arg("bluetooth_packetgen")
        .arg("--out=".to_owned() + out_dir.to_str().unwrap())
        .arg("--include=.")
        .arg("--rust")
        .arg("uci_packets.pdl")
        .output()
        .unwrap();

    eprintln!(
        "Status: {}, stdout: {}, stderr: {}",
        output.status,
        String::from_utf8_lossy(output.stdout.as_slice()),
        String::from_utf8_lossy(output.stderr.as_slice())
    );
}
